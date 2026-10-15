package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-079 (row 6.5l-xiv-e). Cold gate run 16 left three readings open: whether
// the keys in the policy that fork evidence carries are point-checked, what a
// bundle around an entry whose request does not decode is refused as, and
// whether a verifier may use the full tile where the partial one is gone. The
// owner answered all three; the decision rests on c2sp.org/tlog-tiles' own
// words for the third. It lives in three documents that must agree: the
// decision, the plan's list, and the ledger's block.
func TestRunSixteensAcceptanceDecisionIsRecorded(t *testing.T) {
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(raw)), " ")
	}
	decisions := read("DECISIONS.md")
	start := strings.Index(decisions, "## D-079")
	if start < 0 {
		t.Fatal("DECISIONS.md has no D-079")
	}
	d079 := decisions[start:]
	for _, want := range []string{
		"every verifier key it carries is a valid point (§3.1)",
		"`device` follows §16.1's `device_id` grammar",
		"names no device",
		"MAY fetch the full tile in parallel as a fallback in case the partial tile is not available anymore",
		"use its first W hashes",
	} {
		if !strings.Contains(d079, want) {
			t.Errorf("DECISIONS.md D-079 does not say %q", want)
		}
	}
	for _, c := range []struct{ file, want string }{
		{"HARDENING-PLAN.md", "D-079 (taken 2026-10-15"},
		{"BUILD-LOG.md", "DECISION TAKEN — 6.5l-xiv-e"},
		{"BUILD-LOG.md", "1-A, 2-A, 3-A"},
	} {
		if !strings.Contains(read(c.file), c.want) {
			t.Errorf("%s does not say %q", c.file, c.want)
		}
	}
}
