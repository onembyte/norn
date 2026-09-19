package entry

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"testing"
)

// detachedSigner holds a key the way an agent does: it can sign, and it can
// name its public key, and that is all Norn is allowed to assume about it.
type detachedSigner struct{ priv ed25519.PrivateKey }

func (d detachedSigner) Public() crypto.PublicKey { return d.priv.Public() }

func (d detachedSigner) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ed25519.Sign(d.priv, message), nil
}

// The seam exists so that a hardware token behind an agent and a key in memory
// are the same thing to an entry. If this test needs ed25519.PrivateKey to
// compile, there is no seam.
func TestSignAcceptsAnyEd25519Signer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{V: Version, T: "note", Net: make([]byte, NetLen), TS: 1,
		Body: map[string]any{"text": "through a seam"}}

	if err := Sign(env, detachedSigner{priv}, "signer"); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(env.Sigs) != 1 {
		t.Fatalf("got %d signatures", len(env.Sigs))
	}
	if env.Sigs[0].Kid != Kid(pub) {
		t.Errorf("kid = %s, want %s", env.Sigs[0].Kid, Kid(pub))
	}
	ok, err := Verify(env, env.Sigs[0], pub)
	if err != nil || !ok {
		t.Fatalf("a signature made through the seam does not verify: %v", err)
	}
}

// A plain private key must keep working: it is already a crypto.Signer.
func TestSignStillTakesAPrivateKeyDirectly(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{V: Version, T: "note", Net: make([]byte, NetLen), TS: 1,
		Body: map[string]any{"text": "in memory"}}
	if err := Sign(env, priv, "signer"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Verify(env, env.Sigs[0], pub); !ok {
		t.Fatal("does not verify")
	}
}

// §3: every Norn signature is Ed25519. A P-256 key must be refused with an
// error, not signed with and not panicked on -- Secure Enclave and TPM 2.0
// offer exactly this key type, so someone will try.
func TestSignRefusesANonEd25519Signer(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{V: Version, T: "note", Net: make([]byte, NetLen), TS: 1,
		Body: map[string]any{"text": "wrong curve"}}
	if err := Sign(env, priv, "signer"); err == nil {
		t.Fatal("signed with a P-256 key")
	}
	if len(env.Sigs) != 0 {
		t.Fatal("a refused signer still added a signature")
	}
}

// An agent can fail, and the failure must not leave a half-signed entry.
type failingSigner struct{ pub ed25519.PublicKey }

func (f failingSigner) Public() crypto.PublicKey { return f.pub }
func (f failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestSignPropagatesASignerFailure(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{V: Version, T: "note", Net: make([]byte, NetLen), TS: 1,
		Body: map[string]any{"text": "agent said no"}}
	if err := Sign(env, failingSigner{pub}, "signer"); err == nil {
		t.Fatal("a failing signer reported success")
	}
	if len(env.Sigs) != 0 {
		t.Fatal("a failed signature was recorded anyway")
	}
}

// A signer that returns something other than a 64-byte Ed25519 signature is a
// broken or hostile agent; the entry must not carry the result.
type lyingSigner struct{ pub ed25519.PublicKey }

func (l lyingSigner) Public() crypto.PublicKey { return l.pub }
func (l lyingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return []byte("not a signature"), nil
}

func TestSignRefusesAMalformedSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{V: Version, T: "note", Net: make([]byte, NetLen), TS: 1,
		Body: map[string]any{"text": "short"}}
	if err := Sign(env, lyingSigner{pub}, "signer"); err == nil {
		t.Fatal("accepted a 15-byte signature")
	}
	if len(env.Sigs) != 0 {
		t.Fatal("a malformed signature was recorded")
	}
}
