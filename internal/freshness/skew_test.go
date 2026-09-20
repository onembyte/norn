package freshness

import (
	"testing"
	"time"
)

// `GOSSIP.md` part 5 lets the wall clock do exactly one thing: raise
// `CLOCK_SKEW`. It words the test as `|wall − quorum_time| > Δclock`, which is
// right only at the instant of a direct fetch of a freshly cosigned head --
// and wrong the rest of the time, because a log that has not been cosigned for
// two hours produces the same number on a node whose clock is perfect.
//
// The two are told apart by what the node already knows: if its clock were
// right, `wall − quorum_time` would equal the monotonic age it has been
// measuring all along. The difference between those two is the skew, and
// nothing else is.

const witnessAt = 1_760_000_000

func TestASkewedClockIsDetected(t *testing.T) {
	var c Clock
	quorumTime := time.Unix(witnessAt, 0)
	c.Observe(quorumTime, 0)

	// The checkpoint was adopted just now (age 0), and this node thinks it is
	// two hours later than the witnesses do.
	skew, ok := c.Skew(quorumTime, 0, quorumTime.Add(2*time.Hour))
	if !ok {
		t.Fatal("a node with a witness clock can compute skew")
	}
	if skew != 2*time.Hour {
		t.Errorf("skew = %v, want 2h", skew)
	}
}

// The case that makes the naive formula wrong. The node's clock is correct and
// the *log* is two hours stale: `wall − quorum_time` is two hours, and the
// skew is zero. A node that alarmed here would report a clock problem for
// every log outage -- and `GOSSIP.md`'s own T5 says skew and staleness are
// different findings, since a skewed node must raise CLOCK_SKEW and **not** go
// degraded.
func TestAStaleLogIsNotASkewedClock(t *testing.T) {
	var c Clock
	quorumTime := time.Unix(witnessAt, 0)
	c.Observe(quorumTime, 0)

	// Two hours of monotonic time have passed with no newer cosignature, and
	// the wall clock agrees exactly.
	skew, ok := c.Skew(quorumTime, 2*time.Hour, quorumTime.Add(2*time.Hour))
	if !ok {
		t.Fatal("no skew reading")
	}
	if skew != 0 {
		t.Errorf("skew = %v, want 0: a stale log was reported as a wrong clock", skew)
	}

	// And the same moment is genuinely stale, which is the finding that
	// belongs to it.
	age, _ := c.Age(quorumTime, 2*time.Hour)
	if (Limits{Staleness: 10 * time.Minute}).State(age, true) != Degraded {
		t.Error("a two-hour-old view must be degraded")
	}
}

// A clock that is behind is as wrong as one that is ahead, and the sign says
// which -- an operator fixing it needs the direction.
func TestAClockBehindWitnessTimeIsNegativeSkew(t *testing.T) {
	var c Clock
	quorumTime := time.Unix(witnessAt, 0)
	c.Observe(quorumTime, 0)

	skew, ok := c.Skew(quorumTime, 0, quorumTime.Add(-2*time.Hour))
	if !ok {
		t.Fatal("no skew reading")
	}
	if skew != -2*time.Hour {
		t.Errorf("skew = %v, want -2h", skew)
	}
}

// With no witness time there is nothing to compare the wall clock against, so
// there is no skew reading -- not a skew of zero, which would read as a
// verified-correct clock.
func TestWithoutAClockThereIsNoSkew(t *testing.T) {
	var c Clock
	if _, ok := c.Skew(time.Unix(witnessAt, 0), 0, time.Unix(witnessAt, 0)); ok {
		t.Error("a node that has seen no cosignature reported its clock as checked")
	}
}

func TestSkewIsReportedOnlyBeyondTheThreshold(t *testing.T) {
	limits := Limits{Staleness: 10 * time.Minute, MaxSkew: 5 * time.Minute}

	for _, tc := range []struct {
		skew time.Duration
		want bool
	}{
		{0, false},
		{4 * time.Minute, false},
		{5 * time.Minute, false}, // the threshold itself is tolerated
		{5*time.Minute + time.Second, true},
		{-5*time.Minute - time.Second, true}, // and in both directions
		{2 * time.Hour, true},
	} {
		if got := limits.SkewIsSignificant(tc.skew); got != tc.want {
			t.Errorf("significant(%v) = %v, want %v", tc.skew, got, tc.want)
		}
	}
}

// A threshold of zero means "not configured", and must not turn every node
// into a permanent alarm.
func TestAnUnconfiguredThresholdUsesTheDefault(t *testing.T) {
	limits := Limits{Staleness: 10 * time.Minute}

	if limits.SkewIsSignificant(time.Minute) {
		t.Error("a one-minute skew alarmed with no threshold configured")
	}
	if !limits.SkewIsSignificant(2 * time.Hour) {
		t.Error("a two-hour skew must alarm even with the default threshold")
	}
}
