package sshagent

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fake agent encodes its own frames rather than calling into the package
// under test: a framing bug that cancelled itself out would be invisible.

func wireString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func frame(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

func wireEd25519Blob(pub ed25519.PublicKey) []byte {
	return append(wireString([]byte("ssh-ed25519")), wireString(pub)...)
}

// fakeAgent answers one request at a time however the test says to.
type fakeAgent struct {
	identities func() []byte // full payload of the identities answer
	sign       func(blob, data []byte) []byte
	path       string
}

func startFake(t *testing.T, f *fakeAgent) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "na")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f.path = filepath.Join(dir, "s")

	listener, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					var size [4]byte
					if _, err := readFull(conn, size[:]); err != nil {
						return
					}
					payload := make([]byte, binary.BigEndian.Uint32(size[:]))
					if _, err := readFull(conn, payload); err != nil {
						return
					}
					switch payload[0] {
					case 11: // request identities
						conn.Write(frame(f.identities()))
					case 13: // sign request
						blobLen := binary.BigEndian.Uint32(payload[1:5])
						blob := payload[5 : 5+blobLen]
						rest := payload[5+blobLen:]
						dataLen := binary.BigEndian.Uint32(rest[:4])
						conn.Write(frame(f.sign(blob, rest[4:4+dataLen])))
					default:
						conn.Write(frame([]byte{5}))
					}
				}
			}()
		}
	}()
	return f.path
}

func readFull(conn net.Conn, into []byte) (int, error) {
	read := 0
	for read < len(into) {
		n, err := conn.Read(into[read:])
		if err != nil {
			return read, err
		}
		read += n
	}
	return read, nil
}

func honestAgent(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey) *fakeAgent {
	t.Helper()
	return &fakeAgent{
		identities: func() []byte {
			payload := []byte{12}
			payload = binary.BigEndian.AppendUint32(payload, 1)
			payload = append(payload, wireString(wireEd25519Blob(pub))...)
			return append(payload, wireString([]byte("test key"))...)
		},
		sign: func(_, data []byte) []byte {
			sig := ed25519.Sign(priv, data)
			blob := append(wireString([]byte("ssh-ed25519")), wireString(sig)...)
			return append([]byte{14}, wireString(blob)...)
		},
	}
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestKeysAndSigningAgainstAFake(t *testing.T) {
	pub, priv := keypair(t)
	socket := startFake(t, honestAgent(t, pub, priv))

	client, err := Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	keys, err := client.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !keys[0].Public.Equal(pub) {
		t.Fatalf("keys = %+v", keys)
	}
	if keys[0].Comment != "test key" {
		t.Errorf("comment = %q", keys[0].Comment)
	}

	signer, err := client.Signer(pub)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("norn/entry/v1\nsomething to sign")
	sig, err := signer.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, message, sig) {
		t.Fatal("the agent's signature does not verify")
	}
	if got, ok := signer.Public().(ed25519.PublicKey); !ok || !got.Equal(pub) {
		t.Errorf("Public() = %v", signer.Public())
	}
}

// The property that matters most: whatever an agent hands back is checked
// before it leaves this package. A hostile or broken agent must not be able to
// put an invalid signature into the log.
func TestASignatureByAnotherKeyIsRefused(t *testing.T) {
	pub, _ := keypair(t)
	_, otherPriv := keypair(t)

	fake := honestAgent(t, pub, nil)
	fake.sign = func(_, data []byte) []byte {
		sig := ed25519.Sign(otherPriv, data)
		blob := append(wireString([]byte("ssh-ed25519")), wireString(sig)...)
		return append([]byte{14}, wireString(blob)...)
	}
	socket := startFake(t, fake)

	client, err := Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	signer, err := client.Signer(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(nil, []byte("message"), crypto.Hash(0)); err == nil {
		t.Fatal("accepted a signature by a different key")
	}
}

func TestAgentFailureIsAnError(t *testing.T) {
	pub, priv := keypair(t)
	fake := honestAgent(t, pub, priv)
	fake.sign = func([]byte, []byte) []byte { return []byte{5} } // SSH_AGENT_FAILURE
	socket := startFake(t, fake)

	client, _ := Dial(socket)
	defer client.Close()
	signer, err := client.Signer(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(nil, []byte("m"), crypto.Hash(0)); err == nil {
		t.Fatal("a refusal was reported as success")
	}
}

func TestWrongResponseTypeIsAnError(t *testing.T) {
	pub, priv := keypair(t)
	fake := honestAgent(t, pub, priv)
	fake.sign = func([]byte, []byte) []byte { return []byte{12, 0, 0, 0, 0} }
	socket := startFake(t, fake)

	client, _ := Dial(socket)
	defer client.Close()
	signer, _ := client.Signer(pub)
	if _, err := signer.Sign(nil, []byte("m"), crypto.Hash(0)); err == nil {
		t.Fatal("accepted an identities answer as a signature")
	}
}

func TestAnotherAlgorithmIsRefused(t *testing.T) {
	pub, priv := keypair(t)
	fake := honestAgent(t, pub, priv)
	fake.sign = func(_, data []byte) []byte {
		// A well-formed blob that claims to be RSA, carrying a signature that
		// would otherwise verify: only the algorithm name is wrong.
		blob := append(wireString([]byte("ssh-rsa")), wireString(ed25519.Sign(priv, data))...)
		return append([]byte{14}, wireString(blob)...)
	}
	socket := startFake(t, fake)

	client, _ := Dial(socket)
	defer client.Close()
	signer, _ := client.Signer(pub)
	if _, err := signer.Sign(nil, []byte("m"), crypto.Hash(0)); err == nil {
		t.Fatal("accepted a signature blob announcing another algorithm")
	}
}

// A verifier fetches from a log it does not trust; a CLI talks to an agent it
// does not control either. An announced length must not be an allocation.
func TestAnOversizedResponseIsRefused(t *testing.T) {
	pub, priv := keypair(t)
	fake := honestAgent(t, pub, priv)
	socket := startFake(t, fake)

	client, err := Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Speak to the socket directly: announce a frame far past the cap.
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if MaxResponseBytes <= 0 {
		t.Fatal("there is no response cap")
	}

	raw := &Client{conn: conn}
	oversize := make([]byte, 4)
	binary.BigEndian.PutUint32(oversize, uint32(MaxResponseBytes+1))
	if _, err := raw.readResponse(oversize); err == nil {
		t.Fatal("accepted a frame larger than the cap")
	}
}

func TestNonEd25519KeysAreSkipped(t *testing.T) {
	pub, priv := keypair(t)
	fake := honestAgent(t, pub, priv)
	fake.identities = func() []byte {
		payload := []byte{12}
		payload = binary.BigEndian.AppendUint32(payload, 2)
		rsa := append(wireString([]byte("ssh-rsa")), wireString([]byte("not a real key"))...)
		payload = append(payload, wireString(rsa)...)
		payload = append(payload, wireString([]byte("an rsa key"))...)
		payload = append(payload, wireString(wireEd25519Blob(pub))...)
		return append(payload, wireString([]byte("the ed25519 one"))...)
	}
	socket := startFake(t, fake)

	client, _ := Dial(socket)
	defer client.Close()
	keys, err := client.Keys()
	if err != nil {
		t.Fatalf("an agent holding an RSA key must still be usable: %v", err)
	}
	if len(keys) != 1 || !keys[0].Public.Equal(pub) {
		t.Fatalf("keys = %+v, want only the Ed25519 one", keys)
	}
}

func TestSignerForAnAbsentKey(t *testing.T) {
	pub, priv := keypair(t)
	other, _ := keypair(t)
	socket := startFake(t, honestAgent(t, pub, priv))

	client, _ := Dial(socket)
	defer client.Close()
	if _, err := client.Signer(other); err == nil {
		t.Fatal("returned a signer for a key the agent does not hold")
	}
}

// Pure Ed25519 signs the message whole. A caller asking for a pre-hashed
// signature is asking for something this agent path cannot honour.
func TestPreHashedSigningIsRefused(t *testing.T) {
	pub, priv := keypair(t)
	socket := startFake(t, honestAgent(t, pub, priv))

	client, _ := Dial(socket)
	defer client.Close()
	signer, _ := client.Signer(pub)
	if _, err := signer.Sign(nil, make([]byte, 64), crypto.SHA512); err == nil {
		t.Fatal("accepted a pre-hash option")
	}
}

func TestDialingNothing(t *testing.T) {
	dir, err := os.MkdirTemp("", "na")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if _, err := Dial(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("dialled a socket that is not there")
	}
}

func TestOpenReportsAMissingEnvironment(t *testing.T) {
	t.Setenv(SocketEnv, "")
	_, err := Open()
	if err == nil {
		t.Fatal("Open succeeded with no agent configured")
	}
	if !errors.Is(err, ErrNoAgent) {
		t.Errorf("err = %v, want ErrNoAgent", err)
	}
	if !strings.Contains(err.Error(), SocketEnv) {
		t.Errorf("the error should name %s: %v", SocketEnv, err)
	}
}
