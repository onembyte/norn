package enrollreq

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
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

// Cold-model gate run 6, defect H10 -- and the class behind it.
//
// Run 5 reported two request negatives refused by their own broken signature
// rather than by the rule they name. 6.5c fixed those two. Run 6 found two
// more, and checking the whole directory afterwards found eleven of fifteen.
// 6.5b's own log says a fix should "close the class, not the instance", and one
// checkpoint later I fixed the instances.
//
// So the property is enforced over the directory, not a list. Every case
// declares whether its signature is valid; the declaration is checked against
// the file; and only a case that is *about* the signature may declare it
// broken. A new negative cannot be added without answering the question.

func TestEveryRequestNegativeDeclaresItsSignatureHonestly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name      string `json:"name"`
			Why       string `json:"why"`
			Signature string `json:"signature"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 20 {
		t.Fatalf("%d cases; the directory has more than that", len(doc.Cases))
	}

	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			switch c.Signature {
			case "valid", "broken":
			default:
				t.Fatalf("declares signature %q; a negative must say whether its "+
					"signature covers its own bytes, or nobody can tell which rule "+
					"refuses it", c.Signature)
			}

			// Only a case about the signature may have a broken one. Anything
			// else is refused by Ed25519 before its own rule is reached, which
			// is the defect this test exists for.
			if c.Signature == "broken" {
				// Two kinds of case may carry a broken signature: one that is
				// *about* the signature, and one whose fault is the key the
				// signature would verify under. A 31-byte `device_pk` cannot
				// verify anything, so that rule cannot be pinned independently
				// by any construction -- §12.1 says so rather than pretending.
				about := strings.Contains(c.Name, "sig") || strings.Contains(c.Why, "sign") ||
					strings.Contains(c.Why, "unsigned") ||
					strings.Contains(c.Name, "device-pk")
				if !about {
					t.Errorf("%s is not about the signature (%q) and carries a broken one, "+
						"so it is refused by Ed25519 and the rule it names is never reached",
						c.Name, c.Why)
				}
				return
			}
			// A case whose fault is the bech32m wrapper carries the valid
			// request inside it; nothing outside the wrapper can read the
			// signature, and the generator computes the declaration from the
			// bytes it wrote.
			text, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", c.Name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := bech32m.Decode(strings.TrimSpace(string(text))); err != nil {
				t.Skipf("the wrapper is this case's fault: %v", err)
			}
			if !signatureCoversItsOwnBytes(t, c.Name) {
				t.Error("declares a valid signature and does not have one")
			}
		})
	}
}

// The directory's whole purpose, which nothing was checking.
//
// `trust-bad/` has had a loop asserting every case is refused since Phase 0.
// `requests-bad/` never did: individual tests named individual files, so a
// rule could be switched off and the only signal was a case nobody had thought
// to name. Found by a mutation that removed §16.2's padding rules and passed.
func TestEveryRequestNegativeIsRefused(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct{ Name, Why string } `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	net := shippedNet(t)

	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", c.Name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			request, err := DecodeText(strings.TrimSpace(string(body)))
			if err != nil {
				return
			}
			if err := Check(request, net); err == nil {
				t.Errorf("accepted a request that must be refused (%s)", c.Why)
			}
		})
	}
}

func shippedNet(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Net string `json:"net"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(doc.Net)/2)
	for i := range out {
		var b int
		if _, err := fmt.Sscanf(doc.Net[2*i:2*i+2], "%02x", &b); err != nil {
			t.Fatal(err)
		}
		out[i] = byte(b)
	}
	return out
}
