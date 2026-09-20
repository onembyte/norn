package cbor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cold-model gate run 5, defect G9. §4.0 states two resource limits as MUSTs
// and then says neither is reachable by a valid entry -- which is true, and is
// why no vector exercised either. Run 5 removed both (`NORN_NOLIMITS`,
// `NORN_NODEPTH`) and passed 597/597. A limit stated and never tested is a
// limit a second implementer may skip, and these two exist precisely for input
// that is not valid.

func TestHostileInputIsRefusedByTheProfile(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "entries-hostile")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatalf("the hostile-input vectors are missing: %v", err)
	}
	var doc struct {
		Cases []struct{ Name, Says string } `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 2 {
		t.Fatalf("%d hostile cases; §4.0 states two limits", len(doc.Cases))
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(dir, c.Name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			value, err := Decode(body)
			if err == nil {
				t.Fatalf("accepted hostile input, decoding to %T", value)
			}
			if !strings.Contains(err.Error(), c.Says) {
				t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.Says)
			}
		})
	}
}
