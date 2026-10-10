package specdoc

import (
	"strings"
	"testing"
)

// D-072 (e). Under `quorum none` nobody corroborates a checkpoint and there is
// no clock, so a node that writes its interface on such a policy does so on
// the log operator's word alone. v1 keeps that possible -- the roots may lower
// the policy, and some networks mean it -- but never by accident: an enforcing
// node refuses to start on it unless its configuration says so, and a node
// whose policy is lowered under it says so on a cadence until it restarts.
// These are the sentences nornd is built to; a reader of SPEC alone must find
// every one of them.
func TestAnEnforcingNodeNeverRunsOnNoQuorumByAccident(t *testing.T) {
	doc := load(t)
	failure, ok := doc.Section("13.2")
	if !ok {
		t.Fatal("§13.2 is missing")
	}
	text := strings.Join(strings.Fields(failure.Body), " ")
	for _, phrase := range []string{
		"An effective policy of `quorum none`",
		"prevents startup in `owner` and `watchdog` unless the node is configured with `allow_no_quorum`",
		"`observe` always starts",
		"A policy lowered to `quorum none` while the node runs does not stop it",
		"repeats an alarm on the degraded cadence until it restarts",
	} {
		if !strings.Contains(text, phrase) {
			t.Errorf("§13.2 does not state D-072 (e): missing %q", phrase)
		}
	}
}
