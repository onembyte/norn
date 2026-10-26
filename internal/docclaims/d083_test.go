package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-083 replaces D-082 (3)'s key comparison: a returning key is still a
// changed record, and the specification and the recorded answer must agree.
func TestRunNineteensFrozenSetDecisionIsRecorded(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(raw)), " ")
	}
	t.Run("the specification keeps the same version", func(t *testing.T) {
		spec := read("SPEC.md")
		start, end := strings.Index(spec, "## 11. "), strings.Index(spec, "### 11.1 ")
		if start < 0 || end <= start {
			t.Fatal("SPEC.md must have §11 rule 3 before §11.1")
		}
		for _, phrase := range []string{
			"only while its record at the held head is the one at the prefix — the same `version` (§5.3) at both ends, so the same key and routes",
			"a device that any entry revoked, re-enrolled or rotated after the split is removed, whatever key it ends with, since nothing written after the split is trusted and the old key may be the reason it rotated (D-082 (3), D-083).",
		} {
			if !strings.Contains(spec[start:end], phrase) {
				t.Errorf("SPEC.md §11 must say %q", phrase)
			}
		}
	})
	t.Run("D-083 is recorded as A", func(t *testing.T) {
		decisions := read("DECISIONS.md")
		start := strings.Index(decisions, "## D-083")
		if start < 0 {
			t.Error("DECISIONS.md must record D-083 with **A**")
		} else {
			decision := decisions[start+len("## D-083"):]
			if end := strings.Index(decision, "## D-"); end >= 0 {
				decision = decision[:end]
			}
			if !strings.Contains(decision, "**A**") {
				t.Error("DECISIONS.md D-083 must record **A**")
			}
		}
		if !strings.Contains(read("HARDENING-PLAN.md"), "D-083 (taken 2026-10-25") {
			t.Error("HARDENING-PLAN.md must list D-083 with its date")
		}
		ledger := read("BUILD-LOG.md")
		if !strings.Contains(ledger, "## DECISION TAKEN — G15:") || strings.Contains(ledger, "## DECISION NEEDED — G15:") {
			t.Error("BUILD-LOG.md must record DECISION TAKEN — G15")
		}
	})
}
