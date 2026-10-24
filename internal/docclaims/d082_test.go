package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-082 (row G9), parts 2–4. Each answer belongs in its own SPEC section,
// beside the rule it clarifies; the decision, plan and ledger must agree.
// The later lane adds part 1's head and restart sentences here.
func TestRunEighteensTrustFrozenSetAndBindingDecisionsAreRecorded(t *testing.T) {
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(raw)), " ")
	}
	between := func(doc, from, to string) string {
		start := strings.Index(doc, from)
		if start < 0 {
			t.Fatalf("missing section %q", from)
		}
		end := strings.Index(doc[start+len(from):], to)
		if end < 0 {
			t.Fatalf("missing section %q after %q", to, from)
		}
		return doc[start : start+len(from)+end]
	}
	spec := read("SPEC.md")
	for _, c := range []struct {
		from, to string
		phrases  []string
	}{
		{"## 8. ", "### 8.1 ", []string{
			"reader that has replayed the log through the rotation; one holding only `norn.trust` sees `log-signature`",
			"A trust file issued later for the same network names the same initial key (§9.4)",
			"v1 retires no log key, in the log or out of it (D-072 (d), D-074 (a), D-082 (2))",
		}},
		{"### 9.4 ", "## 10. ", []string{
			"**Every trust file for a network names the same initial `log_key` and `policy`** (D-082 (2)).",
			"the `log_key` entry that published it is `dup-key`, every one whose `prev` chains through it is `stale-state`",
			"A reader trusts a later key or policy only by replaying the entry that publishes it.",
			"v1 remedies it with a new network, a new genesis and trust file, and has no verifier-side retirement (D-072 (d))",
		}},
		{"## 11. ", "### 11.1 ", []string{
			"each with its `wg_pk` and the routes its enrollment granted as of the common prefix, and only while its `wg_pk` at the held head is that same key",
			"a device whose key changed after the split is removed, since the old key may be the reason it rotated (D-082 (3))",
		}},
		{"### 11.1 ", "## 12. ", []string{
			"reader that has replayed the log through the rotation; one holding only the trust file answers `held`",
			"it does not yet trust the key the evidence is signed with (D-080, D-082 (2))",
		}},
		{"### 8.1 ", "## 9. ", []string{
			"its closed set of members, each of its type: `v` 1, a text `t`, a 16-byte `net`, a uint `ts`, a map `body`, well-formed `sigs`",
			"Binding is structural: what replay judges against the anchor or the state, such as `net` against `anchor.net`, and a type's body rules beyond the field that names the device, are not part of it (D-082 (4)).",
		}},
	} {
		section := between(spec, c.from, c.to)
		for _, phrase := range c.phrases {
			if !strings.Contains(section, phrase) {
				t.Errorf("SPEC.md %s does not say %q", c.from, phrase)
			}
		}
	}
	decisions := read("DECISIONS.md")
	start := strings.Index(decisions, "## D-082")
	if start < 0 || !strings.Contains(decisions[start:], "**1-A, 2-A, 3-A, 4-A**") {
		t.Error("DECISIONS.md D-082 must record all four answers")
	}
	if !strings.Contains(read("HARDENING-PLAN.md"), "D-082 (taken 2026-10-24") {
		t.Error("HARDENING-PLAN.md must list D-082 with its date")
	}
	ledger := read("BUILD-LOG.md")
	block := between(ledger, "## DECISION TAKEN — G8:", "## DECISION TAKEN — F6:")
	if !strings.Contains(block, "(global rule 14a): 1-A, 2-A, 3-A, 4-A") || strings.Contains(ledger, "## DECISION NEEDED — G8") {
		t.Error("BUILD-LOG.md G8 must record the owner's four answers as taken")
	}
	runbook := between(read("ENROLLMENT.md"), "| R7 |", "| R8 |")
	for _, phrase := range []string{
		"so nodes that have not yet replayed the rotation still verify",
		"is remedied by a new network, a new genesis and trust file, since every trust file for a network names its initial key (§9.4, D-082 (2))",
	} {
		if !strings.Contains(runbook, phrase) {
			t.Errorf("ENROLLMENT.md R7 does not say %q", phrase)
		}
	}
}
