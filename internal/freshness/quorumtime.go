// Package freshness is the node's clock.
//
// A node's wall clock is untrusted (A11): a machine whose time is wrong, or
// has been set wrong, must not be able to decide that a stale peer table is
// current. `GOSSIP.md` part 5 replaces it with witness time -- the latest
// instant that enough independent witnesses have vouched for -- and everything
// in this package is built on that one substitution.
package freshness

import (
	"sort"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/policy"
)

// QuorumTime is the latest instant the policy is satisfied: the newest T such
// that the witnesses whose cosignature is at least T meet the quorum. It
// reports false when no instant does, which is the same condition as having no
// quorum at all -- and also what `quorum none` yields, because a network that
// requires no corroboration has nobody vouching for the time either.
//
// `GOSSIP.md` words this as "the k-th newest cosignature timestamp", which is
// exactly right for a flat threshold and undefined for a nested policy: `group
// top 1 inner friend` has no single k. Evaluating the policy at each candidate
// instant gives the same answer for the flat case and a defined one for the
// rest.
func QuorumTime(rules *policy.Policy, cosignatures []cosign.Cosignature) (time.Time, bool) {
	if rules == nil || !rules.RequiresCosignatures() {
		return time.Time{}, false
	}

	// Only the instants a witness actually signed at can be the answer: the
	// satisfied set only changes as T passes one of them.
	candidates := make([]time.Time, 0, len(cosignatures))
	for _, c := range cosignatures {
		candidates = append(candidates, c.Time)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].After(candidates[j]) })

	for _, t := range candidates {
		var vouching []string
		for _, c := range cosignatures {
			if !c.Time.Before(t) {
				vouching = append(vouching, rules.Label(c.Name))
			}
		}
		if rules.Satisfied(vouching) {
			return t, true
		}
	}
	return time.Time{}, false
}
