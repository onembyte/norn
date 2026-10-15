package proof

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/refusal"
)

// Removing the last hash must recover the sound bundle byte for byte. A
// truncated or otherwise broken proof would not isolate exact consumption.
func TestAPaddedInclusionProofIsRefusedAndItsUnpaddedTwinAccepts(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var manifest struct{ Codes map[string]string }
	if err := json.Unmarshal(read("proofs-bad/cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Codes["padded-proof"] != "inclusion" {
		t.Error("proofs-bad/padded-proof must be coded inclusion")
	}
	b, err := Decode(read("proofs-bad/padded-proof.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Check(shippedAnchor(t)); err == nil {
		t.Error("Go accepts padded-proof; SPEC states inclusion")
	} else if code, _ := refusal.CodeOf(err); code != refusal.Inclusion {
		t.Fatalf("Go answers %q (%v), SPEC states inclusion", code, err)
	}
	if len(b.Proof) == 0 {
		t.Fatal("padded proof is empty")
	}
	b.Proof = b.Proof[:len(b.Proof)-1]
	repaired, err := b.Encode()
	if err != nil || !bytes.Equal(repaired, read("proofs/nas.bundle")) {
		t.Fatalf("removing one hash must recover proofs/nas.bundle: %v", err)
	}
	if err := b.Check(shippedAnchor(t)); err != nil {
		t.Fatalf("Go refuses the unpadded twin: %v", err)
	}
}
