package keyfile_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/sshagent"
)

// Norn writes and reads this format by hand, so the tests check it against the
// implementation that defines it. Both directions matter: OpenSSH must accept
// what Norn writes, and Norn must accept what OpenSSH writes.
//
// NORN_REQUIRE_SSH_AGENT=1 (CI sets it) turns "not installed" into a failure.

const requireEnv = "NORN_REQUIRE_SSH_AGENT"

func needTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv(requireEnv) != "" {
				t.Fatalf("%s is set but %s is not installed", requireEnv, tool)
			}
			t.Skipf("%s is not installed; set %s to make this a failure", tool, requireEnv)
		}
	}
}

// shortTempDir keeps Unix socket paths inside the platform limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func publicFromPubFile(t *testing.T, line string) ed25519.PublicKey {
	t.Helper()
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != sshagent.KeyType {
		t.Fatalf("unexpected public key line: %q", line)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != 4+len(sshagent.KeyType)+4+ed25519.PublicKeySize {
		t.Fatalf("blob is %d bytes", len(blob))
	}
	return ed25519.PublicKey(blob[len(blob)-ed25519.PublicKeySize:])
}

// Direction 1: ssh-keygen reads a key Norn wrote, and agrees about the key.
func TestSSHKeygenReadsWhatNornWrites(t *testing.T) {
	needTools(t, "ssh-keygen")
	dir := shortTempDir(t)
	path := filepath.Join(dir, "device.key")

	public, private, err := keyfile.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Write(path, private, "norn-device"); err != nil {
		t.Fatal(err)
	}

	// -y prints the public key of a private key file, which means it parsed it.
	out, err := exec.Command("ssh-keygen", "-y", "-f", path).Output()
	if err != nil {
		t.Fatalf("ssh-keygen refused a key Norn wrote: %v", err)
	}
	if got := publicFromPubFile(t, string(out)); !got.Equal(public) {
		t.Errorf("ssh-keygen read a different key: %x vs %x", got, public)
	}
}

// Direction 2: Norn reads a key ssh-keygen wrote, and the key works.
func TestNornReadsWhatSSHKeygenWrites(t *testing.T) {
	needTools(t, "ssh-keygen")
	dir := shortTempDir(t)
	path := filepath.Join(dir, "id")

	comment := "made-by-ssh-keygen"
	gen := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}

	private, gotComment, err := keyfile.Read(path)
	if err != nil {
		t.Fatalf("Norn could not read an ordinary ssh-keygen key: %v", err)
	}
	if gotComment != comment {
		t.Errorf("comment = %q, want %q", gotComment, comment)
	}

	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	want := publicFromPubFile(t, string(pub))
	if !private.Public().(ed25519.PublicKey).Equal(want) {
		t.Fatal("the key Norn read is not the key ssh-keygen generated")
	}

	// And it is usable where it matters: as an entry signature (§4.2).
	env := &entry.Envelope{V: entry.Version, T: "note", Net: make([]byte, entry.NetLen),
		TS: 1, Body: map[string]any{"text": "signed from a key file"}}
	if err := entry.Sign(env, private, "device"); err != nil {
		t.Fatal(err)
	}
	if ok, err := entry.Verify(env, env.Sigs[0], want); err != nil || !ok {
		t.Fatalf("the signature does not verify: %v", err)
	}
}

// The promise that tier 0 becomes tier 1 with no conversion: the same file an
// agent can load. If this fails, the two key stores are not one format.
func TestSSHAddLoadsAKeyNornWrote(t *testing.T) {
	needTools(t, "ssh-agent", "ssh-add")
	dir := shortTempDir(t)
	socket := filepath.Join(dir, "agent")

	agent := exec.Command("ssh-agent", "-D", "-a", socket)
	agent.Stderr = os.Stderr
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = agent.Process.Kill()
		_, _ = agent.Process.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ssh-agent never created its socket")
		}
		time.Sleep(10 * time.Millisecond)
	}

	path := filepath.Join(dir, "device.key")
	public, private, err := keyfile.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Write(path, private, "norn-device"); err != nil {
		t.Fatal(err)
	}

	add := exec.Command("ssh-add", path)
	add.Env = append(os.Environ(), sshagent.SocketEnv+"="+socket)
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add refused a key Norn wrote: %v: %s", err, out)
	}

	client, err := sshagent.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	keys, err := client.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !keys[0].Public.Equal(public) {
		t.Fatalf("the agent holds %+v, want the key Norn wrote", keys)
	}
}

// An encrypted key must be refused clearly, and the message must say what to do
// about it -- this is the documented boundary between tier 0 and tier 1.
func TestAnEncryptedKeyIsRefusedWithAnAnswer(t *testing.T) {
	needTools(t, "ssh-keygen")
	dir := shortTempDir(t)
	path := filepath.Join(dir, "id")

	gen := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "a passphrase", "-f", path)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}

	_, _, err := keyfile.Read(path)
	if err == nil {
		t.Fatal("read an encrypted key without a passphrase")
	}
	if !errors.Is(err, keyfile.ErrEncrypted) {
		t.Errorf("err = %v, want ErrEncrypted", err)
	}
	if !strings.Contains(err.Error(), "ssh-add") {
		t.Errorf("the error should point at the agent: %v", err)
	}
}
