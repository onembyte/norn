package forkevidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/evrefusal"
)

func TestEvidenceVersionsHaveExactKeySetsAndTheirSoundTwinsProveTheFork(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(t *testing.T, name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, "fork", name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, name := range []string{"bad-v1-split-keys", "bad-v2-without-split-keys"} {
		t.Run(name, func(t *testing.T) {
			var m struct{ Codes map[string]string }
			if err := json.Unmarshal(read(t, "cases.json"), &m); err != nil {
				t.Fatal(err)
			}
			if m.Codes[name] != "schema" {
				t.Error("fork/" + name + " must be coded schema")
			}
			raw := read(t, name+".cbor")
			if _, err := Parse(raw); err == nil {
				t.Fatal("Go accepts " + name + "; SPEC states schema")
			} else if code, _ := evrefusal.CodeOf(err); code != evrefusal.Schema {
				t.Fatalf("Go answers %q (%v), SPEC states schema", code, err)
			}
			value, err := cbor.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			doc := value.(map[string]any)
			twin := "evidence.cbor"
			wantVersion, wantKeys := uint64(1), 11
			if name == "bad-v2-without-split-keys" {
				twin = "evidence-v1.cbor"
				wantVersion, wantKeys = 2, 7
			}
			if doc["version"] != wantVersion || len(doc) != wantKeys {
				t.Fatal("wrong version or key set")
			}
			doc["version"] = uint64(2)
			if wantVersion == 2 {
				doc["version"] = uint64(1)
			}
			repaired, err := cbor.Encode(doc)
			if err != nil || !bytes.Equal(repaired, read(t, twin)) {
				t.Fatalf("changing only the version must recover the sound twin: %v", err)
			}
			ev, err := Parse(repaired)
			if err != nil {
				t.Fatal(err)
			}
			anchor := shippedAnchor(t, root)
			if _, err := Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy); err != nil {
				t.Fatal("Go refuses sound twin", err)
			}
		})
	}
}
