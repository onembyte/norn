package enrollreq

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/bech32m"
	"github.com/onembyte/norn/internal/cbor"
)

// Cold-model gate run 5, defects G3 and G4. A negative that is refused for
// some rule other than the one it is named for does not pin that rule: run 5
// disabled the §4.0 map-key cap and §16.1's `expires > ts` outright and still
// passed 597/597, because both vectors were patched after signing and so died
// at Ed25519 instead.
//
// §4.0 states the construction rule these violated: either the patch
// canonicalises away and the original signature still verifies, or the request
// is re-signed over the patched preimage. The check below is the second half.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

// signatureCoversItsOwnBytes reports whether the request's `sig` verifies over
// the preimage of the bytes as they actually ship -- which is what makes the
// file's *only* fault the rule it names.
func signatureCoversItsOwnBytes(t *testing.T, name string) bool {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := bech32m.Decode(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatalf("%s is not decodable bech32m, so it tests the wrapper: %v", name, err)
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Skipf("%s is outside the CBOR profile, so its signature cannot be checked "+
			"with a strict decoder; the generator asserts it instead: %v", name, err)
	}
	m, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is not a CBOR map", name)
	}
	sig, _ := m["sig"].([]byte)
	pk, _ := m["device_pk"].([]byte)
	if len(sig) != ed25519.SignatureSize || len(pk) != ed25519.PublicKeySize {
		t.Fatalf("%s carries no usable sig/device_pk", name)
	}
	body := map[string]any{}
	for k, v := range m {
		if k != "sig" {
			body[k] = v
		}
	}
	encoded, err := cbor.Encode(body)
	if err != nil {
		t.Fatalf("re-encoding %s: %v", name, err)
	}
	return ed25519.Verify(pk, append([]byte(PreimagePrefix), encoded...), sig)
}

func TestARuleNegativeIsRefusedByItsOwnRule(t *testing.T) {
	// Each of these names a rule; each must be the *only* thing wrong.
	for _, c := range []struct{ name, rule string }{
		{"expires-at-ts", "expires must be after ts"},
		{"oversize-label-key", "map key must be 1-23 bytes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			text, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", c.name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeText(strings.TrimSpace(string(text)))
			if err == nil {
				t.Fatal("accepted a request that must be refused")
			}
			if !strings.Contains(err.Error(), c.rule) {
				t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.rule)
			}
			if !signatureCoversItsOwnBytes(t, c.name) {
				t.Error("the signature does not cover the bytes that ship, so a verifier " +
					"missing this rule still refuses the file and the rule is not pinned")
			}
		})
	}
}

// The control: a case that is *about* the signature must still fail to verify.
func TestTheForgedRequestStillDoesNotVerify(t *testing.T) {
	if signatureCoversItsOwnBytes(t, "forged-signature") {
		t.Error("forged-signature verifies, so nothing in the suite forces a request " +
			"verifier to call Ed25519")
	}
}
