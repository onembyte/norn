package freshness

import "time"

// Freshness states, from `GOSSIP.md` part 5's machine, plus the one that
// machine cannot express.
const (
	Fresh     = "fresh"
	Degraded  = "degraded"
	HardStale = "hard_stale"
	// Unknown means no witness has vouched for any instant, so age has no
	// answer -- not "it is fine", and not "it is stale".
	Unknown = "unknown"
)

// Clock is witness time carried forward by a monotonic elapsed reading.
//
// It is given durations, never timestamps, for the age calculation: the type
// has no way to ask the operating system what time it is, so a node whose wall
// clock is wrong -- or is moved while it runs -- computes exactly the same age
// as one whose clock is right. That is A11 expressed as an API rather than as
// a rule somebody has to remember.
//
// The zero value is a clock that has seen nothing, which answers "unknown".
type Clock struct {
	// best is the newest instant any quorum has vouched for, and seenAt is the
	// monotonic reading when this node learned it. Together they are the
	// node's estimate of now: best + (mono - seenAt).
	best   time.Time
	seenAt time.Duration
	seen   bool
}

// Observe records that a quorum vouched for `quorumTime`, learned at the
// monotonic reading `mono`.
//
// Each observation is a lower bound on witness time now, quorumTime + (now -
// mono), and the clock keeps the largest (§15, D-074 b). That is not the same
// as keeping the newest quorum time: a head cosigned at a newer instant but
// learned long after an older one carries a smaller bound, and taking it
// dragged the estimate of now backwards -- everything the node held then
// looked younger than it had already proven the world to be, which is the one
// direction a freshness check must never fail in. An older instant learned
// later is ignored for the same reason: a peer may legitimately serve a valid
// but older checkpoint.
func (c *Clock) Observe(quorumTime time.Time, mono time.Duration) {
	if c.seen && !quorumTime.Add(-mono).After(c.best.Add(-c.seenAt)) {
		return
	}
	c.best, c.seenAt, c.seen = quorumTime, mono, true
}

// EstimatedNow is witness time carried forward to the monotonic reading
// `mono`. It reports false before any quorum has been observed.
func (c *Clock) EstimatedNow(mono time.Duration) (time.Time, bool) {
	if !c.seen {
		return time.Time{}, false
	}
	return c.best.Add(mono - c.seenAt), true
}

// Age is how old `quorumTime` is at the monotonic reading `mono`, measured
// against this node's estimate of now. It reports false when there is no
// clock at all.
func (c *Clock) Age(quorumTime time.Time, mono time.Duration) (time.Duration, bool) {
	now, ok := c.EstimatedNow(mono)
	if !ok {
		return 0, false
	}
	return now.Sub(quorumTime), true
}

// Limits are the thresholds of the state machine. Staleness is SPEC §4.5's
// `staleness` (S), carried in the log's own params so a network agrees on it.
//
// Hard is S_hard, and it is **opt-in** (GOSSIP part 5): crossing it makes the
// enforcer drop every peer, so a node that was never configured for it stays
// `degraded` -- loud, but not taking the network down by itself because a log
// was unreachable for a weekend. Zero means not configured.
type Limits struct {
	Staleness time.Duration
	Hard      time.Duration
	// MaxSkew is Δclock: how far this node's wall clock may be from witness
	// time before it says so. Node-local like Hard, and for the same reason --
	// it is a fact about this machine, not about the network. Zero means
	// DefaultMaxSkew.
	MaxSkew time.Duration
}

// State names where `age` falls. `haveClock` is the second return of Age: with
// no witness clock the answer is Unknown, never Fresh.
func (l Limits) State(age time.Duration, haveClock bool) string {
	// The states are tested in this order and the first that holds is the
	// answer (§8.1, D-060). `hard_stale` comes BEFORE `fresh` because the two
	// are both true whenever `S_hard < elapsed <= S`, and `S` moves by root
	// quorum: testing `fresh` first would let a `params` entry raise every
	// node's local hard limit out of reach, which is the opposite of what
	// makes it local (D-034 makes the same argument for the witness policy).
	// A hard limit means what the operator typed.
	switch {
	case !haveClock:
		return Unknown
	case l.Hard > 0 && age > l.Hard:
		return HardStale
	case age <= l.Staleness:
		return Fresh
	default:
		return Degraded
	}
}

// defaultStaleness is SPEC §4.5's `staleness`, in case a state carries none.
const defaultStaleness = 600 * time.Second

// LimitsFrom reads `staleness` from a log's replayed params and pairs it with
// this node's own S_hard.
//
// The split is deliberate: `staleness` is in the log because the whole network
// should agree on when a view is too old to trust, while S_hard drops every
// peer and so stays a local decision (D-034 makes the same argument for the
// witness policy). A params map missing it, or carrying something that is not
// a count of seconds, falls back to the §4.5 default -- never to "never
// stale", which would silently disable the check.
func LimitsFrom(params map[string]any, hard time.Duration) Limits {
	staleness := defaultStaleness
	switch v := params["staleness"].(type) {
	case uint64:
		staleness = time.Duration(v) * time.Second
	case int64:
		if v > 0 {
			staleness = time.Duration(v) * time.Second
		}
	}
	return Limits{Staleness: staleness, Hard: hard}
}
