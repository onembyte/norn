package specdoc

import (
	"path/filepath"
	"strings"
	"testing"
)

// Each run-18 Go case has an explicit placement, code and literal normative
// citation. In particular, a capped size is never described as a served log.
func TestRunEighteenGoCasesAreIndexedAtTheirOwnLayers(t *testing.T) {
	doc := load(t)
	index, _ := doc.Section("12")
	coverage, _ := doc.Section("12.1")
	for _, c := range []struct{ dir, name, file, code, section, says string }{
		{"proofs-bad", "index-outside-tree", "index-outside-tree.bundle", "inclusion", "10.1", "the index is outside the tree"},
		{"checkpoints-bad", "47-signed-text-not-utf8", "47-signed-text-not-utf8.checkpoint", "note", "10.1", "text or a line that is not UTF-8"},
		{"checkpoints-good", "cosignature-time-at-the-cap", "cosignature-time-at-the-cap.checkpoint", "accept", "7", "at most 2⁶³−1"},
		{"checkpoints-good", "size-at-the-cap", "size-at-the-cap.checkpoint", "accept", "6", "at most 2⁶³−1"},
		{"grown-log", "malformed-partial-with-good-full", "malformed-partial-tile.bin", "tiles", "10.1", "a served hash tile disagrees with the rebuilt tree"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var m struct {
				Codes map[string]string
				Rules map[string]struct{ Section, Says string }
			}
			readJSON(t, filepath.Join(vectorRoot(t), c.dir, "cases.json"), &m)
			r := m.Rules[c.name]
			if m.Codes[c.name] != c.code || r.Section != c.section || r.Says != c.says {
				t.Fatalf("case must cite §%s as %s: %+v", c.section, c.code, r)
			}
			section, ok := doc.Section(r.Section)
			if !ok {
				t.Fatal("missing normative section")
			}
			found := false
			for _, line := range strings.Split(section.Body, "\n") {
				found = found || strings.Contains(line, r.Says)
			}
			if !found {
				t.Fatal("rule must quote one raw normative line")
			}
			if !strings.Contains(index.Body, "`"+c.dir+"/") || !strings.Contains(coverage.Body, "`"+c.dir+"/"+c.file+"`") {
				t.Fatal("§12 and §12.1 must index the directory and full file")
			}
		})
	}
}
