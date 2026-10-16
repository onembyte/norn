package specdoc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These hints are raw lines, not whitespace-normalised reconstructions. A
// receiving implementation must find every cited rule where it was named.
func TestRunSixteenPlainRuleCasesCiteOneRawLineAndTheirFullPaths(t *testing.T) {
	doc := load(t)
	coverage := coverage(t)
	for _, tc := range []struct {
		dir   string
		names []string
	}{
		{"heads-run16", []string{"stranger-log-id", "stranger-pi-id", "stranger-del", "stranger-three-bytes", "policy-log-only", "forged-pi-without-quorum"}},
		{"served-large-bad", []string{"level-one-byte-changed"}},
		{"receipt-bad", []string{"origin-extended.note"}},
		{"fork", []string{"bad-v1-split-keys", "bad-v2-without-split-keys"}},
		{"proofs", []string{"nas-rotate", "laptop-revoke"}},
	} {
		raw, err := os.ReadFile(filepath.Join(vectorsDir(), tc.dir, "cases.json"))
		if err != nil {
			t.Error(err)
			continue
		}
		type rule struct{ Section, Says string }
		var manifest struct {
			Rules    map[string]rule
			Requests struct{ Rules map[string]rule }
		}
		if err := json.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		for _, name := range tc.names {
			r, ok := manifest.Rules[name]
			if !ok {
				t.Errorf("%s/%s lacks a rule", tc.dir, name)
				continue
			}
			section, ok := doc.Section(r.Section)
			if !ok || r.Says == "" || strings.Contains(r.Says, "\n") || !strings.Contains(section.Body, r.Says) {
				t.Errorf("%s/%s: %+v is not in one raw line of its section", tc.dir, name, r)
			}
			path := tc.dir + "/" + name
			if !strings.Contains(coverage, "`"+path+"`") {
				t.Errorf("§12.1 must name full case path `%s`", path)
			}
		}
		for name, r := range manifest.Requests.Rules {
			section, ok := doc.Section(r.Section)
			if !ok || r.Says == "" || strings.Contains(r.Says, "\n") || !strings.Contains(section.Body, r.Says) {
				t.Errorf("request %s lacks one raw rule line", name)
			}
			if !strings.Contains(coverage, "`heads-run16/"+name+"`") {
				t.Errorf("§12.1 must name the request case %s", name)
			}
		}
	}
}
