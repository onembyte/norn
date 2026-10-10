package agent

import (
	"fmt"

	"github.com/onembyte/norn/internal/endpoint"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/replay"
)

// frozenSet is §11 rule 3 (D-072 (a)): what a node that has proved its log
// forked keeps enforcing. It is the devices proven at the common prefix --
// this node's own entries replayed to `split` -- whose keys are also proven
// at the head it holds, with the routes their enrollment granted as of the
// prefix.
//
// The prefix is the last state both branches agree on, so it is the last one
// a node can still call authorized once it knows the log signs whatever suits
// it; a split view's rogue was enrolled after it, on the victim's branch, and
// goes. The intersection with the held head is what keeps the set from
// growing: a device this branch revoked after the split is in the prefix and
// stays out. It is by key, not by device: a device that rotated after the
// split is in the prefix under its old key and at the head under its new one,
// and neither key is proven at both -- the old one may be the reason it
// rotated.
//
// When the prefix cannot be established -- no split claimed, or this node's
// branch does not reach it or has another root there -- it returns no peers
// and the reason, and the node fails closed. The reason is "" otherwise.
func (a *Agent) frozenSet(held *logclient.Result, split int64, splitRoot [32]byte,
	own peertable.Key) ([]peertable.Peer, endpoint.Report, string) {
	if split <= 0 {
		return nil, endpoint.Report{}, "the evidence claims no common prefix"
	}
	if held == nil || held.Tree == nil || held.Checkpoint.Size < split ||
		int64(len(held.Served)) < split {
		return nil, endpoint.Report{}, fmt.Sprintf(
			"this node's branch does not reach the split at %d entries", split)
	}
	root, err := held.Tree.HeadAt(split)
	if err != nil {
		return nil, endpoint.Report{}, fmt.Sprintf(
			"this node's branch does not reach the split at %d entries: %v", split, err)
	}
	if root != splitRoot {
		return nil, endpoint.Report{}, fmt.Sprintf(
			"this node's branch has another root at the split at %d entries", split)
	}

	// The prefix is evaluated at the held head's time, the latest instant a
	// quorum vouched for: a device whose enrollment expired since the split
	// is not proven there either (§5.3).
	prefix := *held
	prefix.State = replay.Replay(a.replayAnchor(), held.Served[:split])
	atPrefix, report := a.desired(&prefix, own)
	atHead, _ := a.desired(held, own)
	proven := make(map[peertable.Key]bool, len(atHead))
	for _, peer := range atHead {
		proven[peer.Key] = true
	}
	kept := atPrefix[:0]
	for _, peer := range atPrefix {
		if proven[peer.Key] {
			kept = append(kept, peer)
		}
	}
	return kept, report, ""
}
