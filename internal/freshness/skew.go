package freshness

import "time"

// DefaultMaxSkew is Δclock when a node has not been told otherwise.
//
// It cannot be tight. At a direct fetch the newest cosignature is already as
// old as the log's checkpoint cadence plus the witnesses' round trip, so a
// threshold near zero would alarm on every healthy network. Five minutes
// absorbs that comfortably while still catching the failure this exists for: a
// machine whose clock is wrong by hours, which is what a dead RTC battery, a
// missing NTP server or a wrong time zone actually produce.
const DefaultMaxSkew = 5 * time.Minute

// Skew is how far this node's wall clock is from witness time, at the monotonic
// reading `mono`. Positive means the node believes it is later than the
// witnesses do.
//
// `GOSSIP.md` part 5 words the test as `|wall − quorum_time| > Δclock`. That is
// the right number only at the instant a freshly cosigned head is fetched
// directly from the log; away from it the expression measures the log's
// staleness as well, and a node with a perfect clock reports a clock problem
// every time the log goes quiet.
//
// The two are separable with what the node already has. If its clock were
// right, `wall − quorum_time` would equal the monotonic age it has been
// measuring since adoption. The difference between those is the skew, and it
// reduces to GOSSIP's formula exactly when the age is zero.
//
// It reports false when no quorum has been observed: there is then nothing to
// compare the wall clock against, and a skew of zero would read as a clock
// that had been checked and found correct.
func (c *Clock) Skew(quorumTime time.Time, mono time.Duration, wall time.Time) (time.Duration, bool) {
	age, ok := c.Age(quorumTime, mono)
	if !ok {
		return 0, false
	}
	return wall.Sub(quorumTime) - age, true
}

// SkewIsSignificant reports whether a skew is worth an alarm, in either
// direction: a clock that is behind is as wrong as one that is ahead.
func (l Limits) SkewIsSignificant(skew time.Duration) bool {
	max := l.MaxSkew
	if max <= 0 {
		max = DefaultMaxSkew
	}
	if skew < 0 {
		skew = -skew
	}
	return skew > max
}
