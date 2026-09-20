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
		Cases []struct {
			Name, Says string
			Accepted   bool `json:"accepted"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	// Each limit needs both sides, or it is bounded in one direction only.
	var accepted, refused int
	for _, c := range doc.Cases {
		if c.Accepted {
			accepted++
		} else {
			refused++
		}
	}
	if accepted < 2 || refused < 2 {
		t.Fatalf("%d accepted and %d refused; §4.0's two limits each need a case at the "+
			"limit and a case past it, or a decoder enforcing the wrong value passes",
			accepted, refused)
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(dir, c.Name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			value, err := Decode(body)
			if c.Accepted {
				// The far side of a boundary. Without it the limit is only
				// bounded from one direction, and a decoder enforcing 4 or 64
				// where the profile says 8 passes everything.
				if err != nil {
					t.Fatalf("refused input that sits exactly at the limit: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted hostile input, decoding to %T", value)
			}
			if !strings.Contains(err.Error(), c.Says) {
				t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.Says)
			}
		})
	}
}
