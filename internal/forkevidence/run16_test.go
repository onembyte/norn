package forkevidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/evrefusal"
)

// Both mutations start with the same sound version-2 evidence, leaving the
// other proofs intact so no earlier fault can mask exact consumption.
func TestPaddedConsistencyProofsAreRefusedAndTheirUnpaddedTwinsProveTheFork(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, "fork", path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var manifest struct{ Codes map[string]string }
	if err := json.Unmarshal(read(t, "cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	anchor := shippedAnchor(t, root)
	for _, name := range []string{"bad-padded-proof", "bad-padded-split-proof"} {
		t.Run(name, func(t *testing.T) {
			if manifest.Codes[name] != "proof" {
				t.Error("fork/" + name + " must be coded proof")
			}
			ev, err := Parse(read(t, name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy); err == nil {
				t.Error("Go accepts " + name + "; SPEC states proof")
			} else if code, _ := evrefusal.CodeOf(err); code != evrefusal.Proof {
				t.Fatalf("Go answers %q (%v), SPEC states proof", code, err)
			}
			path := &ev.Proof
			if name == "bad-padded-split-proof" {
				path = &ev.SplitProofHeld
			}
			if len(*path) == 0 {
				t.Fatal("padded proof is empty")
			}
			*path = (*path)[:len(*path)-1]
			repaired, err := ev.Encode()
			if err != nil || !bytes.Equal(repaired, read(t, "evidence.cbor")) {
				t.Fatalf("removing one hash must recover fork/evidence.cbor: %v", err)
			}
			if _, err := Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy); err != nil {
				t.Fatalf("Go refuses the unpadded twin: %v", err)
			}
		})
	}
}
