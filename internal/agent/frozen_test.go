package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
)

// heldServed is a node holding the served fixture log: a real, cosigned head
// with its entries and its tree, as a node holds them after a cycle.
func heldServed(t *testing.T) (*Agent, *logclient.Result) {
	t.Helper()
	a := newAgent(t, reconcile.Owner, servedLog(t), peertable.NewFake(), &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	held := a.held()
	if held == nil || held.Tree == nil || len(held.Served) == 0 {
		t.Fatal("the node holds no head with entries")
	}
	return a, held
}

// provenKeysIn is what §5.3 proves in a state at the held head's time, by
// key: computed here from the state, not by the agent's own path.
func provenKeysIn(t *testing.T, st *state.State, held *logclient.Result) map[peertable.Key]string {
	t.Helper()
	out := map[peertable.Key]string{}
	for _, id := range proven.Devices(st, proven.EvaluationTime(held)) {
		key, err := keyOf(st.Devices[id].WgPk)
		if err != nil {
			t.Fatal(err)
		}
		out[key] = id
	}
	return out
}

// D-072 (a), §11 rule 3. A node that has proved a fork keeps enforcing the
// devices proven at the common prefix AND at the head it holds: whatever
// was added after the split goes, and whatever this branch revoked after it
// stays out. The split is chosen in the fixture so that both kinds of device
// exist; otherwise the test would prove nothing about either.
func TestTheFrozenSetIsThePrefixIntersectedWithTheHeldHead(t *testing.T) {
	a, held := heldServed(t)
	atHead := provenKeysIn(t, held.State, held)

	var split int64
	var atSplit map[peertable.Key]string
	for s := int64(1); s < held.Checkpoint.Size; s++ {
		prefix := provenKeysIn(t, replay.Replay(a.replayAnchor(), held.Served[:s]), held)
		kept, added, revoked := 0, 0, 0
		for key := range atHead {
			if _, ok := prefix[key]; ok {
				kept++
			} else {
				added++
			}
		}
		for key := range prefix {
			if _, ok := atHead[key]; !ok {
				revoked++
			}
		}
		// All three kinds must exist at the chosen split, or a frozen set that
		// keeps nothing -- or keeps everything -- would pass.
		if kept > 0 && added > 0 && revoked > 0 {
			split, atSplit = s, prefix
			break
		}
	}
	if split == 0 {
		t.Fatal("the fixture has no split with a device proven on both sides of it, one " +
			"enrolled after it and one revoked after it")
	}
	root, err := held.Tree.HeadAt(split)
	if err != nil {
		t.Fatal(err)
	}

	peers, _, why := a.frozenSet(held, split, root, peertable.Key{})
	if why != "" {
		t.Fatalf("a split this node can establish was refused: %s", why)
	}
	got := map[peertable.Key]bool{}
	for _, peer := range peers {
		got[peer.Key] = true
	}
	for key, id := range atHead {
		_, kept := atSplit[key]
		if kept && !got[key] {
			t.Errorf("%s is proven at the split and at the held head, and was dropped", id)
		}
		if !kept && got[key] {
			t.Errorf("%s was enrolled after the split and is still enforced", id)
		}
	}
	for key, id := range atSplit {
		if _, ok := atHead[key]; !ok && got[key] {
			t.Errorf("%s was revoked after the split on this branch and came back: the set grew", id)
		}
	}
	for key := range got {
		if _, ok := atHead[key]; !ok {
			t.Errorf("the frozen set holds %s, which the held head does not prove", key.Short())
		}
	}
}

// §11 rule 3: with no common prefix established, the node fails closed.
func TestTheFrozenSetIsEmptyWhenTheSplitCannotBeEstablished(t *testing.T) {
	a, held := heldServed(t)
	root, err := held.Tree.HeadAt(10)
	if err != nil {
		t.Fatal(err)
	}
	other := root
	other[0] ^= 0x01
	for _, c := range []struct {
		name  string
		split int64
		root  [32]byte
		why   string
	}{
		{"no split claimed", 0, [32]byte{}, "no common prefix"},
		{"the branch does not reach the split", held.Checkpoint.Size + 1, root, "does not reach"},
		{"another root at the split", 10, other, "another root"},
	} {
		t.Run(c.name, func(t *testing.T) {
			peers, _, why := a.frozenSet(held, c.split, c.root, peertable.Key{})
			if len(peers) != 0 {
				t.Errorf("%d peers kept; with no common prefix the node fails closed", len(peers))
			}
			if !strings.Contains(why, c.why) {
				t.Errorf("reason %q does not say %q", why, c.why)
			}
		})
	}
	if peers, _, why := a.frozenSet(nil, 10, root, peertable.Key{}); len(peers) != 0 || why == "" {
		t.Error("a node holding nothing kept peers or gave no reason")
	}
}

// The node's own key is never a peer, at the split as at the head.
func TestTheFrozenSetLeavesOutTheNodesOwnKey(t *testing.T) {
	a, held := heldServed(t)
	atHead := provenKeysIn(t, held.State, held)
	var own peertable.Key
	for key := range atHead {
		own = key
		break
	}
	split := held.Checkpoint.Size - 1
	root, err := held.Tree.HeadAt(split)
	if err != nil {
		t.Fatal(err)
	}
	peers, _, _ := a.frozenSet(held, split, root, own)
	if slices.ContainsFunc(peers, func(p peertable.Peer) bool { return p.Key == own }) {
		t.Error("the node's own key is in its frozen set")
	}
}
