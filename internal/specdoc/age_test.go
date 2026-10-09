package specdoc

import (
	"strings"
	"testing"
)

// D-074 (b). §8.1's condition 4 defined `elapsed` as the node's monotonic
// reading since it learned *this* checkpoint's quorum time, and §15 defined a
// checkpoint's age as the node's estimate of now minus its quorum time. They
// agree only while the held head carries the newest quorum time the node has
// seen; a grown head cosigned by slower witnesses can be `fresh` under one and
// `degraded` under the other, and §13.2 then empties the peer table under one
// reading and not the other. There is one age now, §15's, with its bound, its
// boundaries, and what wall time and clock skew may never do to it.
func TestThereIsOneCheckpointAge(t *testing.T) {
	doc := load(t)
	bundle, ok := doc.Section("8.1")
	if !ok {
		t.Fatal("§8.1 is missing")
	}
	text := strings.Join(strings.Fields(bundle.Body), " ")
	for _, phrase := range []string{
		"`elapsed` is the checkpoint's **age** as §15 defines it",
		"never the monotonic time since the node learned this checkpoint",
		"compared as durations, not rounded",
		"`CLOCK_SKEW` (§15) changes none of these states",
	} {
		if !strings.Contains(text, phrase) {
			t.Errorf("§8.1 does not point condition 4 at §15's age: missing %q", phrase)
		}
	}
	if strings.Contains(text, "monotonic reading when it learned this checkpoint's quorum time (§5.3)") {
		t.Error("§8.1 still defines its own `elapsed`; there is one age, §15's")
	}

	distribution, ok := doc.Section("15")
	if !ok {
		t.Fatal("§15 is missing")
	}
	text = strings.Join(strings.Fields(distribution.Body), " ")
	for _, phrase := range []string{
		"the largest of the lower bounds",
		"a newer quorum time does not replace a larger bound",
		"an older time MUST NOT move that estimate backwards",
		"An age is never negative",
		"time the machine was suspended",
		"err toward `fresh` by at most that gap",
		"SHOULD use a monotonic source that counts suspended time",
		"`detect/staleness.json`'s `observed` cases",
	} {
		if !strings.Contains(text, phrase) {
			t.Errorf("§15 does not define the one age with its bound: missing %q", phrase)
		}
	}
}
