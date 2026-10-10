package cosign

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
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

// A cosignature is checked with NORN-ED25519-v1: the identity key's line is a
// listed witness's line that does not verify, refused as `cosignature`.
func TestACosignatureByTheIdentityKeyIsRefused(t *testing.T) {
	key, sig := identityKeyAndSignature(t)
	payload := note.KeyIDFor("w.example", key, note.AlgCosignature)
	payload = binary.BigEndian.AppendUint64(payload, 1_760_000_000)
	payload = append(payload, sig...)
	signed := "example.org/log\n1\nAAAA\n\n" + note.SignatureLine("w.example", payload) + "\n"
	got, err := Verify(signed, []string{note.CosignerVerifierKey("w.example", key)})
	if err == nil {
		t.Fatalf("a cosignature by the identity key was accepted: %+v", got)
	}
	if code, _ := refusal.CodeOf(err); code != refusal.Cosignature {
		t.Errorf("refused as %q, want %q (%v)", code, refusal.Cosignature, err)
	}
}
