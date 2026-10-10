package entry

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// identityKeyAndSignature is the signature SPEC §3.1 exists to refuse
// (D-072 (c)): the identity point as a key, R the identity and S = 0. The
// equation [0]B = O + [k]O holds whatever k is, so Go's crypto/ed25519 accepts
// it over every message -- a key anyone can sign anything with. The identity
// is not of order L, so NORN-ED25519-v1 refuses it.
func identityKeyAndSignature(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, sig := make([]byte, 32), make([]byte, 64)
	key[0], sig[0] = 1, 1
	if !ed25519.Verify(key, []byte("any message"), sig) {
		t.Fatal("crypto/ed25519 no longer accepts the identity's signature, so this test shows nothing")
	}
	return key, sig
}

// An entry signature is checked with NORN-ED25519-v1, so the identity key
// signs no entry.
func TestAnEntrySignedByTheIdentityKeyDoesNotVerify(t *testing.T) {
	key, sig := identityKeyAndSignature(t)
	env := &Envelope{V: 1, T: "note", Net: bytes.Repeat([]byte{1}, 16), TS: 1,
		Body: map[string]any{"text": "hello"}}
	ok, err := Verify(env, Signature{Kid: Kid(key), Role: "signer", Sig: sig}, key)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("an entry signed by the identity key verified")
	}
}
