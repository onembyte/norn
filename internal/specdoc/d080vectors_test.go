package specdoc

import (
	"path/filepath"
	"strings"
	"testing"
)

// Row 6.5l-xv-i, Go half (lane BX): every file it ships is cited by its full
// path in §12.1, and its manifest's rule quotes one raw line of the section it
// names. D-082 (4) adds five structural binding cases to the same contract.
func TestD080GoCasesAreIndexedAndCiteRawRules(t *testing.T) {
	doc := load(t)
	coverage, _ := doc.Section("12.1")
	for dir, files := range map[string][]string{
		"fork":       {"evidence-rotated-key.cbor"},
		"grown-log":  {"full-tile-trailing-bytes.bin", "full-tile-truncated.bin", "full-bundle-trailing-bytes.bin"},
		"proofs-bad": {"oversize-entry.bundle", "rotate-v2.bundle", "rotate-no-ts.bundle"},
		"proofs":     {"forged.bundle", "halfsigned.bundle", "enroll-other-net.bundle", "rotate-small-order-pk.bundle", "rotate-open-body.bundle", "enroll-open-body.bundle"},
	} {
		var m struct {
			Rules map[string]struct{ Section, Says string }
		}
		readJSON(t, filepath.Join(vectorRoot(t), dir, "cases.json"), &m)
		for _, file := range files {
			if !strings.Contains(coverage.Body, "`"+dir+"/"+file+"`") {
				t.Errorf("§12.1 must cite full path %s/%s", dir, file)
			}
			name := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(file, ".cbor"), ".bin"), ".bundle")
			rule, ok := m.Rules[name]
			if !ok {
				t.Errorf("%s/%s needs a rule", dir, file)
				continue
			}
			section, ok := doc.Section(rule.Section)
			if !ok {
				t.Fatalf("missing §%s", rule.Section)
			}
			found := false
			for _, line := range strings.Split(section.Body, "\n") {
				found = found || rule.Says != "" && strings.Contains(line, rule.Says)
			}
			if !found {
				t.Errorf("%s/%s must cite one raw line of §%s: %q", dir, file, rule.Section, rule.Says)
			}
		}
	}
}
