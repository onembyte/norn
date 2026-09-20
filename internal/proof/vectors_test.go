package proof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
)

// Cold-model gate run 5, defect G12. §8.1 said the bundle format carries
// "domain `norn/proof/v1`", and the six-key table below that sentence has no
// domain in it, no signature for a domain prefix to separate, and the string
// appears nowhere else in the document. The bundles are byte-canonical
// six-key maps, so the domain is emitted nowhere -- and an implementer cannot
// tell whether they are required to produce it or to check for it.
//
// The table and the artifact are now compared, so the section cannot describe
// a format the suite does not ship.

var reKeyRow = regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|")

func TestTheBundleTableDescribesTheShippedBundles(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(spec)
	start := strings.Index(text, "### 8.1")
	if start < 0 {
		t.Fatal("§8.1 is missing")
	}
	end := strings.Index(text[start:], "\n\nChecking a bundle")
	if end < 0 {
		t.Fatal("§8.1 no longer has its key table")
	}
	var described []string
	for _, m := range reKeyRow.FindAllStringSubmatch(text[start:start+end], -1) {
		described = append(described, m[1])
	}
	sort.Strings(described)
	if len(described) == 0 {
		t.Fatal("§8.1 describes no keys")
	}

	bundles, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors",
		"proofs", "*.bundle"))
	if err != nil || len(bundles) == 0 {
		t.Fatalf("no proof bundles ship: %v", err)
	}
	raw, err := os.ReadFile(bundles[0])
	if err != nil {
		t.Fatal(err)
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := value.(map[string]any)
	if !ok {
		t.Fatal("a bundle is not a CBOR map")
	}
	var actual []string
	for key := range m {
		actual = append(actual, key)
	}
	sort.Strings(actual)

	if strings.Join(described, ",") != strings.Join(actual, ",") {
		t.Errorf("§8.1 and the shipped bundles disagree about the format:\n"+
			"  §8.1 describes %v\n  %s carries   %v",
			described, filepath.Base(bundles[0]), actual)
	}
}

// And the claim that started it: a domain string nothing emits.
func TestTheBundleClaimsNoDomainItDoesNotCarry(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(spec), "norn/proof/v1") {
		t.Error("§8.1 names a domain `norn/proof/v1` that appears in no field, covers " +
			"no signature, and is emitted by nothing: an implementer cannot tell " +
			"whether they must produce it")
	}
}

// §12.1 named four proof-bundle refusals -- wrong entry, foreign checkpoint,
// tampered proof, wrong log key -- and shipped none of them. Run 5 built two
// itself to check its work, which is the reader doing the suite's job.

func TestEveryProofNegativeIsRefused(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "proofs-bad")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatalf("the proof negatives are missing: %v", err)
	}
	var doc struct {
		LogKey string                        `json:"log_key"`
		Cases  []struct{ Name, Says string } `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 4 {
		t.Fatalf("%d proof negatives; §12.1 names four", len(doc.Cases))
	}

	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(dir, c.Name+".bundle"))
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := Decode(body)
			if err != nil {
				if !strings.Contains(err.Error(), c.Says) {
					t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.Says)
				}
				return
			}
			err = bundle.Check([]string{doc.LogKey})
			if err == nil {
				t.Fatal("accepted a bundle that proves nothing about this log")
			}
			if !strings.Contains(err.Error(), c.Says) {
				t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.Says)
			}
		})
	}
}
