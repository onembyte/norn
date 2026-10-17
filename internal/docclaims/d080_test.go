package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-080 (row 6.5l-xv-c). Cold gate run 17 left five readings open: blanks
// after a policy line's last field, which log keys verify fork evidence, a
// malformed full tile or bundle standing in for a deleted partial one, whether
// the 4096-byte cap binds a trust file's policy, and what "decodes under
// §16.1" covers in a bundle's binding. The owner answered all five. It lives
// in three documents that must agree: the decision, the plan's list, and the
// ledger's block.
func TestRunSeventeensAcceptanceDecisionIsRecorded(t *testing.T) {
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(raw)), " ")
	}
	decisions := read("DECISIONS.md")
	start := strings.Index(decisions, "## D-080")
	if start < 0 {
		t.Fatal("DECISIONS.md has no D-080")
	}
	d080 := decisions[start:]
	for _, want := range []string{
		"spaces and tabs after the last field are not part of it and add no field",
		"the log keys the reader trusts (§9.4: the trust file's, plus every `log_key` of a state it has accepted)",
		"must itself be a well-formed full tile or bundle",
		"MUST fetch the full path before answering `unserved`",
		"bounded only by `MAX_TRUST_BYTES`",
		"the request's signature and network are not part of it",
		"an `entry` longer than `MAX_ENTRY_BYTES` is `bundle`",
	} {
		if !strings.Contains(d080, want) {
			t.Errorf("DECISIONS.md D-080 does not say %q", want)
		}
	}
	if !strings.Contains(read("HARDENING-PLAN.md"), "D-080 (taken 2026-10-17") {
		t.Error("HARDENING-PLAN.md §2 does not list D-080 with its date")
	}
	// The row that records the answers is not the block; the block itself
	// must carry them, so a row edited alone cannot stand in for it.
	ledger := read("BUILD-LOG.md")
	start = strings.Index(ledger, "## DECISION TAKEN — 6.5l-xv-c")
	if start < 0 {
		t.Fatal("BUILD-LOG.md has no DECISION TAKEN — 6.5l-xv-c")
	}
	block := ledger[start:]
	if end := strings.Index(block[1:], "## DECISION TAKEN"); end > 0 {
		block = block[:end+1]
	}
	if !strings.Contains(block, "(global rule 14a): 1-A, 2-A, 3-A, 4-A, 5-A") {
		t.Error("the 6.5l-xv-c block does not record the owner's five answers")
	}
}
