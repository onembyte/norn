package freshness

import (
	"testing"
	"time"
)

// `GOSSIP.md` part 5: the node records `(mono_now, quorum_time)` on every
// adoption, and age is measured by *monotonic* elapsed time from there. The
// wall clock cannot appear in this calculation -- not "should not": the Clock
// is given elapsed durations and has no way to ask what time it is, so a
// machine whose clock is wrong, or is moved, computes exactly the same age.

const (
	minute = time.Minute
	S      = 10 * time.Minute // staleness, SPEC §4.5 default
	SHard  = time.Hour
)

func TestAgeIsElapsedSinceTheNewestQuorumTime(t *testing.T) {
	var c Clock
	witness := time.Unix(1_760_000_000, 0)
	c.Observe(witness, 5*minute) // monotonic reading at adoption

	age, ok := c.Age(witness, 8*minute)
	if !ok {
		t.Fatal("a clock that has observed a quorum time can answer")
	}
	if age != 3*minute {
		t.Errorf("age = %v, want 3m", age)
	}
}

// A view built on an older checkpoint is older, even while the node has seen a
// newer quorum time elsewhere -- age is a property of what is being enforced,
// not of the best thing the node has heard about.
func TestAnOlderCheckpointIsOlder(t *testing.T) {
	var c Clock
	newest := time.Unix(1_760_000_000, 0)
	c.Observe(newest, 5*minute)

	age, ok := c.Age(newest.Add(-2*minute), 8*minute)
	if !ok {
		t.Fatal("no age")
	}
	if age != 5*minute {
		t.Errorf("age = %v, want 5m (3m elapsed + 2m behind the newest)", age)
	}
}

// A peer serving a valid but older checkpoint must not drag the clock
// backwards: the node has already seen a witness vouch for a later instant,
// and no later evidence can unsee it.
func TestAnOlderObservationDoesNotMoveTheClockBack(t *testing.T) {
	var c Clock
	newest := time.Unix(1_760_000_000, 0)
	c.Observe(newest, 5*minute)
	c.Observe(newest.Add(-30*minute), 6*minute)

	age, ok := c.Age(newest, 7*minute)
	if !ok {
		t.Fatal("no age")
	}
	if age != 2*minute {
		t.Errorf("age = %v, want 2m: an older cosignature moved the clock", age)
	}
}

// Until some witness has vouched for some instant there is no clock, and the
// answer is "I cannot tell" rather than zero -- which would read as brand new.
func TestWithoutAnObservationThereIsNoAge(t *testing.T) {
	var c Clock
	if _, ok := c.Age(time.Unix(1_760_000_000, 0), 5*minute); ok {
		t.Error("a clock that has seen nothing produced an age")
	}
}

func TestTheStateMachine(t *testing.T) {
	limits := Limits{Staleness: S, Hard: SHard}

	for _, tc := range []struct {
		name string
		age  time.Duration
		want string
	}{
		{"new", 0, Fresh},
		{"just inside S", S - time.Second, Fresh},
		// `fresh` is `age ≤ S`, so the boundary itself is still fresh.
		{"exactly S", S, Fresh},
		{"just past S", S + time.Second, Degraded},
		// `degraded` is `S < age ≤ S_hard`, so this boundary is degraded.
		{"exactly S_hard", SHard, Degraded},
		{"past S_hard", SHard + time.Second, HardStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := limits.State(tc.age, true); got != tc.want {
				t.Errorf("state at %v = %q, want %q", tc.age, got, tc.want)
			}
		})
	}
}

// hard-stale is opt-in (GOSSIP part 5): it drops every peer, so a node that
// did not ask for it stays degraded and noisy forever rather than taking the
// network down by itself after a long enough outage.
func TestHardStaleIsOptIn(t *testing.T) {
	limits := Limits{Staleness: S}

	if got := limits.State(30*time.Hour, true); got != Degraded {
		t.Errorf("state = %q, want %q: hard-stale must not happen unless asked for",
			got, Degraded)
	}
}

// No clock, no claim.
func TestNoClockIsUnknownNotFresh(t *testing.T) {
	limits := Limits{Staleness: S, Hard: SHard}

	if got := limits.State(0, false); got != Unknown {
		t.Errorf("state = %q, want %q", got, Unknown)
	}
}

// `staleness` is a log parameter (SPEC §4.5), so a network agrees on it rather
// than each node picking its own. S_hard is not: it is a node's own decision to
// let itself drop every peer.
func TestLimitsComeFromTheLogsParams(t *testing.T) {
	limits := LimitsFrom(map[string]any{"staleness": uint64(60)}, SHard)
	if limits.Staleness != time.Minute {
		t.Errorf("staleness = %v, want 1m", limits.Staleness)
	}
	if limits.Hard != SHard {
		t.Errorf("hard = %v, want %v", limits.Hard, SHard)
	}

	// A params map without it -- or carrying something that is not a number --
	// falls back to §4.5's default rather than to "never stale".
	for _, params := range []map[string]any{nil, {}, {"staleness": "soon"}} {
		if got := LimitsFrom(params, 0).Staleness; got != 600*time.Second {
			t.Errorf("staleness from %v = %v, want the §4.5 default", params, got)
		}
	}
}
