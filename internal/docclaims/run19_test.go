package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Run 19 names which held state supplies each judgment. These clarifications
// belong beside the rules, where a reader of the specification finds them.
func TestRunNineteensHeldStateClarificationsAreStated(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	spec := strings.Join(strings.Fields(string(raw)), " ")
	for _, c := range []struct{ name, from, to, phrase string }{
		{"L11", "### 5.3 ", "## 6. ", "That is the verifier loop's held head (§10) and its restoration after a restart (§13.2); a checkpoint carried inside a bundle (§8.1) or fork evidence (§11.1) is checked under the policy the reader holds now — the trust file's, or the most recently replayed (§9.4) — even when it names the tree head the reader already holds."},
		{"L19", "### 8.1 ", "## 9. ", "Let `elapsed` be condition 4's monotonic duration, `S` be `params.staleness` in the state replayed through the checkpoint the node holds (§4.5) — not the anchor's default, a newer head it has not accepted, or the state at a bundle's entry — and `S_hard` be this node's own hard limit. Then the state is the"},
		{"L18", "## 11. ", "### 11.1 ", "Both proven-set tests judge expiry at the held head's `T` (§5.3): the common prefix has no checkpoint time of its own, and the conflicting head's `T` is not used."},
	} {
		t.Run(c.name, func(t *testing.T) {
			start, end := strings.Index(spec, c.from), strings.Index(spec, c.to)
			if start < 0 || end <= start {
				t.Fatalf("SPEC.md must have %s before %s", c.from, c.to)
			}
			if !strings.Contains(spec[start:end], c.phrase) {
				t.Errorf("SPEC.md %s must say %q", c.from, c.phrase)
			}
		})
	}
}
