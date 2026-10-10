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
