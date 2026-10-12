package specdoc

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The third cold build read two passages against the text around them (row
// 6.5l-xii-e). §5 called a four-field anchor "the pair", and §10's outline,
// headed normative, compared branches before it fetched the entries the
// comparison is computed from, where §10.1's table runs entries, head, fork,
// genesis, tiles. Reading §8.1 for the build's third note showed one point
// made twice. Keep the corrections and refuse the replaced wording.
func TestTheThirdColdBuildsProseFindingsAreFixed(t *testing.T) {
	doc := load(t)
	section := func(t *testing.T, number string) string {
		t.Helper()
		s, ok := doc.Section(number)
		if !ok {
			t.Fatalf("§%s is missing", number)
		}
		return strings.Join(strings.Fields(s.Body), " ")
	}
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }

	t.Run("anchor", func(t *testing.T) {
		body := section(t, "5")
		if want := norm("and **`anchor`** holds four fields of the verifier's trust file (§9):"); !strings.Contains(body, want) {
			t.Errorf("§5 does not say the anchor holds four fields: %q", want)
		}
		if stale := norm("is the pair taken from the verifier's trust file"); strings.Contains(body, stale) {
			t.Errorf("§5 still calls the anchor %q", stale)
		}
	})

	// The outline names each check in the order §10.1 numbers them, so a reader
	// who follows either one refuses a two-fault checkpoint with the same code.
	t.Run("outline order", func(t *testing.T) {
		body := section(t, "10")
		if want := norm("Where a reader needs an order, §10.1's table decides"); !strings.Contains(body, want) {
			t.Errorf("§10 does not defer its order to §10.1: %q", want)
		}
		last := -1
		for _, step := range []string{
			"verify log signature",                        // 3
			"require cp's text is a tlog-checkpoint body", // 4
			"require cp.origin == norn.trust.origin",      // 5
			"verify witness policy",                       // 6, 7
			"entries := fetch the entry bundles",          // 8
			"require root(entries) == cp.root",            // 9
			"if stored_cp exists:",                        // 10
			"require entries[0] is the genesis",           // 11
			"require every served hash tile",              // 12
			"state := replay(trust, entries[0:cp.size])",
		} {
			at := strings.Index(body, norm(step))
			if at < 0 {
				t.Errorf("§10's outline has no %q", step)
				continue
			}
			if at < last {
				t.Errorf("§10's outline has %q out of §10.1's order", step)
			}
			last = at
		}
		if stale := norm("fetch new tiles / entry bundles (TileFetcher / TileFS + PermanentCache) state := replay"); strings.Contains(body, stale) {
			t.Error("§10's outline still fetches the entries after comparing branches")
		}
	})

	t.Run("bundle entry said once", func(t *testing.T) {
		body := section(t, "8.1")
		if n := strings.Count(body, norm("It does **not** prove the device's *current* key")); n != 1 {
			t.Errorf("§8.1 says the bundle does not prove the current key %d times", n)
		}
		if stale := norm("**A bundle proves that its device was enrolled, not which key it uses now.**"); strings.Contains(body, stale) {
			t.Error("§8.1 still repeats the paragraph on what a bundle's entry proves")
		}
		for _, kept := range []string{
			"`proofs/nas.bundle` proves `nas`'s enrolment at index 1",
			"`proofs/cases.json` lists under `installs`",
			"`proven/cases.json`'s `bundles` map",
		} {
			if !strings.Contains(body, norm(kept)) {
				t.Errorf("§8.1 lost the citation %q", kept)
			}
		}
	})
}

// §10 has no numbered steps; §10.1 does, and its step 3 is the log signature.
// Comments that cited step 3 of §10 meant the witness quorum, counted down an
// outline that never numbered itself, and sent a reader who looked it up in
// §10.1 to the wrong check. Every live citation names §10.1's step. The
// records keep the words they were written in.
func TestNoCitationCountsTheOutlinesSteps(t *testing.T) {
	needle := "§10" + " step" // split, so this file does not cite one itself
	root := filepath.Join("..", "..")
	records := map[string]bool{"BUILD-LOG.md": true, "DECISIONS.md": true}
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			switch name {
			case ".git", ".venv", ".gocache", "testdata", "verify-py":
				return filepath.SkipDir
			}
			return nil
		}
		if records[name] || strings.HasPrefix(name, "SPEC-DEFECTS-") || strings.HasPrefix(name, "SPEC-DECISIONS-") {
			return nil
		}
		if !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".md") && !strings.HasSuffix(name, ".py") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, needle) {
				rel, _ := filepath.Rel(root, path)
				found = append(found, rel+":"+strconv.Itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range found {
		t.Errorf("%s cites a step of §10, which numbers none; cite §10.1's", at)
	}
}
