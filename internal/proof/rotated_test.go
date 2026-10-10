package proof

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
)

// §8.1, D-074 (a): a bundle's checkpoint verifies under the log keys the
// reader trusts, not the trust file's alone. A shipped bundle with its
// checkpoint replaced by served-rotated's -- the same head, signed by the key
// the roots published at entry 27 -- is the bundle a log makes after the
// overlap. A reader holding only trust.cbor refuses it as `log-signature`; one
// that has replayed the rotation and trusts the published key accepts it.
func TestABundleUnderARotatedKeyIsCheckedUnderTheKeysTheReaderTrusts(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "proofs", "nas.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := os.ReadFile(filepath.Join(root, "served-rotated", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	bundle.Checkpoint = string(rotated)
	var meta struct {
		SignedBy string `json:"signed_by"`
	}
	blob, err := os.ReadFile(filepath.Join(root, "served-rotated", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(blob, &meta); err != nil {
		t.Fatal(err)
	}
	published, err := hex.DecodeString(meta.SignedBy)
	if err != nil {
		t.Fatal(err)
	}

	fresh := shippedAnchor(t)
	err = bundle.Check(fresh)
	if code, _ := refusal.CodeOf(err); code != refusal.LogSignature {
		t.Errorf("a reader holding only trust.cbor: %q, want log-signature: %v", code, err)
	}
	informed := fresh
	informed.LogKeys = append(append([]string(nil), fresh.LogKeys...), note.VerifierKey(fresh.Origin, published))
	if err := bundle.Check(informed); err != nil {
		t.Errorf("a reader that trusts the published key refused the bundle: %v", err)
	}
}

// The same, as a shipped vector: proofs-rotated/ carries the bundle and the
// key it is signed with, and says both answers.
func TestTheRotatedBundleHasBothAnswers(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors", "proofs-rotated")
	var c struct {
		Bundle   string `json:"bundle"`
		SignedBy string `json:"signed_by"`
		Fresh    string `json:"fresh"`
		Informed string `json:"informed"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "cases.json"))
	if err != nil {
		t.Fatalf("the rotated-bundle vector is missing: %v", err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Fresh != string(refusal.LogSignature) || c.Informed != "accept" {
		t.Fatalf("cases.json says fresh %q, informed %q; want log-signature and accept", c.Fresh, c.Informed)
	}
	blob, err := os.ReadFile(filepath.Join(root, c.Bundle))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	published, err := hex.DecodeString(c.SignedBy)
	if err != nil {
		t.Fatal(err)
	}
	fresh := shippedAnchor(t)
	if code, _ := refusal.CodeOf(bundle.Check(fresh)); code != refusal.LogSignature {
		t.Errorf("a reader holding only trust.cbor: %q, want log-signature", code)
	}
	informed := fresh
	informed.LogKeys = append(append([]string(nil), fresh.LogKeys...), note.VerifierKey(fresh.Origin, published))
	if err := bundle.Check(informed); err != nil {
		t.Errorf("a reader that trusts the published key refused the bundle: %v", err)
	}
}
