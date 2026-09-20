package forkevidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/policy"
)

// Cold-model gate run 5, defect G6. §12.1 claimed two refusals for §11 --
// "evidence for another origin is refused; so is a `fork` between a log and
// its own earlier self" -- and neither shipped as a file. The first is
// exercised by a Go test against the *valid* vector; the second could not be
// exercised at all, because `Build` refuses to produce it. A reader could not
// check either, and run 5 could not check the evidence vector at all, because
// the format it uses is not defined in SPEC.md.

func TestEveryForkNegativeIsRefused(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "fork", "cases.json"))
	if err != nil {
		t.Fatalf("the fork negatives are missing: %v", err)
	}
	var doc struct {
		Cases []struct{ Name, Says string } `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 2 {
		t.Fatalf("%d fork negatives; §12.1 names two", len(doc.Cases))
	}

	anchor := shippedAnchor(t, root)
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(root, "fork", c.Name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			// A negative may fail at either layer: the file may not parse, or
			// it may parse and prove nothing. Both are refusals; neither is an
			// accusation a third party should act on.
			evidence, err := Parse(body)
			if err != nil {
				if !strings.Contains(err.Error(), c.Says) {
					t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.Says)
				}
				return
			}
			_, err = Check(evidence, anchor.Origin, anchor.LogKey, rules.Keys())
			if err == nil {
				t.Fatal("accepted evidence that proves no fork; a reader would act on a " +
					"false accusation")
			}
			if !strings.Contains(err.Error(), c.Says) {
				t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.Says)
			}
		})
	}
}
