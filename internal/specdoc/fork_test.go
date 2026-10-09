package specdoc

import (
	"strings"
	"testing"
)

// D-072 (a), the owner's option D. A proven fork used to leave the interface
// exactly as it was, which left a split view's rogue connected after the
// node had proved the split. Now the node keeps enforcing the last state both
// branches agree on -- the common prefix -- so the enforced set may shrink
// and never grow, and fails closed when no such state can be established.
// The evidence carries the split so a node that only receives the file can
// do the same. These sentences are the contract the agent, the evidence
// reader and the simulator are built to; a reader of SPEC alone must find
// every one of them.
func TestAProvenForkShrinksToTheCommonPrefix(t *testing.T) {
	doc := load(t)
	fork, ok := doc.Section("11")
	if !ok {
		t.Fatal("§11 is missing")
	}
	forkText := strings.Join(strings.Fields(fork.Body), " ")
	for _, phrase := range []string{
		"consume no further authorization state from either branch",
		"**common prefix**: the largest size at which both branches have the same root",
		"proven at the common prefix **and** proven at the head the node itself holds",
		"may only stay the same or shrink; it MUST never grow",
		"fail closed",
		"repeat it",
	} {
		if !strings.Contains(forkText, phrase) {
			t.Errorf("§11 does not state D-072 (a): missing %q", phrase)
		}
	}

	evidence, ok := doc.Section("11.1")
	if !ok {
		t.Fatal("§11.1 is missing")
	}
	evidenceText := strings.Join(strings.Fields(evidence.Body), " ")
	for _, phrase := range []string{
		"`version` | uint | `1` or `2`",
		"| `split` | uint |",
		"| `split_root` | bytes (32) |",
		"| `split_proof_held` | array of bytes (32 each) |",
		"| `split_proof_conflicting` | array of bytes (32 each) |",
		"exactly eleven keys",
		"accuser can understate the split and never overstate it",
		"`split` 0 means no common prefix is claimed",
	} {
		if !strings.Contains(evidenceText, phrase) {
			t.Errorf("§11.1 does not define version 2 evidence: missing %q", phrase)
		}
	}

	failure, ok := doc.Section("13.2")
	if !ok {
		t.Fatal("§13.2 is missing")
	}
	failureText := strings.Join(strings.Fields(failure.Body), " ")
	if !strings.Contains(failureText, "freezes the node's authorization at the common prefix of the two branches (§11)") {
		t.Error("§13.2 still describes a frozen node as leaving its last verified state in force")
	}
}
