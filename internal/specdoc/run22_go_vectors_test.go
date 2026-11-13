package specdoc

import (
	"path/filepath"
	"strings"
	"testing"
)

// These additions cite existing normative words. Clarifying those words is
// a separate row, so a future sentence cannot supply a missing citation here.
func TestRunTwentyTwoGoVectorsCiteExistingSpecPhrases(t *testing.T) {
	doc := load(t)
	for _, dir := range []string{"served-superseded", "served-bad", "quorum-none", "served-upper-witness-name", "served-upper-log-name", "proofs", "proofs-older-head"} {
		t.Run(dir, func(t *testing.T) {
			var meta struct {
				Rules map[string]struct{ Section, Says string }
			}
			readJSON(t, filepath.Join(vectorRoot(t), dir, "cases.json"), &meta)
			names := map[string][]string{
				"served-superseded": {"one-cosignature"}, "served-bad": {"missing-full-hash-tile"}, "quorum-none": {"forged-pi"},
				"served-upper-witness-name": {"name-case"}, "served-upper-log-name": {"name-case"}, "proofs": {"entry-at-the-cap"}, "proofs-older-head": {"laptop-older-head", "nas-older-head"},
			}[dir]
			for _, name := range names {
				rule, ok := meta.Rules[name]
				if !ok || rule.Says == "" {
					t.Errorf("missing %s rule", name)
					continue
				}
				section, ok := doc.Section(rule.Section)
				if !ok {
					t.Errorf("unknown section %s", rule.Section)
					continue
				}
				found := false
				for _, line := range strings.Split(section.Body, "\n") {
					found = found || strings.Contains(line, rule.Says)
				}
				if !found {
					t.Errorf("%s does not cite an existing raw line of §%s: %q", name, rule.Section, rule.Says)
				}
			}
		})
	}
}
