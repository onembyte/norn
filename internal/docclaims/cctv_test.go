package docclaims

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// The upstream bytes are evidence independent of Norn's implementations. The
// derived table states §3.1's answers without performing signature verification.
func TestTheCCTVVectorsAreKeptAsFetched(t *testing.T) {
	dir := filepath.Join(root(t), "testdata", "vectors", "ed25519-cctv")
	raw, err := os.ReadFile(filepath.Join(dir, "PROVENANCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[string]string{}
	row := regexp.MustCompile("(?m)^\\| `([^`]+)` \\| `([0-9a-f]{64})` \\|")
	for _, m := range row.FindAllStringSubmatch(string(raw), -1) {
		if _, ok := recorded[m[1]]; ok {
			t.Fatalf("duplicate provenance digest for %s", m[1])
		}
		recorded[m[1]] = m[2]
	}
	if len(recorded) != 3 {
		t.Fatalf("provenance has %d digests, want 3", len(recorded))
	}
	for _, name := range []string{"ed25519vectors.json", "LICENSE", "README.md"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != recorded[name] {
			t.Errorf("%s has digest %s, PROVENANCE.md records %s", name, got, recorded[name])
		}
	}
}

func TestTheCCTVCaseTableNamesTheFirstDecidingFlag(t *testing.T) {
	dir := filepath.Join(root(t), "testdata", "vectors", "ed25519-cctv")
	read := func(name string, value any) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, value); err != nil {
			t.Fatal(err)
		}
	}
	var vectors []struct {
		Number int
		Flags  []string
	}
	read("ed25519vectors.json", &vectors)
	var table struct {
		Comment string
		Cases   []struct {
			Number        int
			Outcome, Flag string
		}
	}
	read("cases.json", &table)
	if len(vectors) != 914 || len(table.Cases) != 914 {
		t.Fatalf("vectors/cases counts %d/%d, want 914/914", len(vectors), len(table.Cases))
	}
	flagsByNumber := map[int][]string{}
	for _, v := range vectors {
		if _, ok := flagsByNumber[v.Number]; ok {
			t.Fatalf("duplicate vector %d", v.Number)
		}
		flagsByNumber[v.Number] = v.Flags
	}
	order := []string{"low_order_A", "low_order_R", "non_canonical_A", "non_canonical_R", "low_order_component_A", "low_order_component_R"}
	seen := map[int]bool{}
	accepts := 0
	for _, c := range table.Cases {
		flags, ok := flagsByNumber[c.Number]
		if !ok || seen[c.Number] {
			t.Fatalf("unknown or duplicate case %d", c.Number)
		}
		seen[c.Number] = true
		first := ""
		for _, flag := range order {
			if slices.Contains(flags, flag) {
				first = flag
				break
			}
		}
		if first == "" {
			if len(flags) != 0 || c.Number != 305 || c.Outcome != "accept" || c.Flag != "" {
				t.Errorf("case %d: unflagged vector 305 alone must accept without a flag", c.Number)
			}
		} else if c.Outcome != "reject" || c.Flag != first || !slices.Contains(flags, c.Flag) {
			t.Errorf("case %d: outcome %q flag %q, want reject with first carried flag %q", c.Number, c.Outcome, c.Flag, first)
		}
		if c.Outcome == "accept" {
			accepts++
		}
	}
	if accepts != 1 {
		t.Errorf("table has %d accepts, want 1", accepts)
	}
}
