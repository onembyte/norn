package agent

import (
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/trust"
)

// otherGenesis is this network's trust file pinning a genesis the shipped log
// does not have: a trust file for another network, or a corrupted one, handed
// to a node that is then served this log.
func otherGenesis(t *testing.T) *trust.Trust {
	t.Helper()
	doc := *anchor(t)
	wrong := sha256.Sum256([]byte("not this network's genesis"))
	doc.GenesisHash = wrong[:]
	return &doc
}

// SEC-029. Replay aborts on an entry 0 that is not the pinned genesis and
// returns an empty state, and the verifier returned that as a success. In
// owner mode the agent then installed the empty set -- six peers to none,
// with no error and no alarm -- which is the one thing the agent promises
// never to do: a failure never empties the table. A log whose first entry is
// not this network's genesis is not this network's log, and nothing in it is
// a fact about this network.
func TestALogForAnotherGenesisNeverEmptiesTheTable(t *testing.T) {
	for _, mode := range []reconcile.Mode{reconcile.Owner, reconcile.Watchdog} {
		t.Run(string(mode), func(t *testing.T) {
			fake := peertable.NewFake(provenKeys(t)...)
			before, _ := fake.Peers()
			rec := &recorder{}
			a, err := New(Config{Anchor: otherGenesis(t),
				Fetcher: logclient.Dir(filepath.Join(vectors(), "served")),
				Device:  fake, Mode: mode, Emit: rec.emit,
				Now: func() time.Time { return time.Unix(fixtureCosignedAt, 0) }})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Once(); err == nil {
				t.Fatal("a log whose entry 0 is not this network's genesis verified")
			}
			after, _ := fake.Peers()
			if len(after) != len(before) {
				t.Fatalf("the table went from %d peers to %d on a log for another genesis",
					len(before), len(after))
			}
			kinds := rec.kinds()
			if kinds[VerifyFailed] == 0 || kinds[NoStateYet] == 0 {
				t.Errorf("the refusal should be reported as a failed verification with no "+
					"state yet, not as a success: %v", kinds)
			}
		})
	}
}

// The same log from a peer, while this node's own log is unreachable, is not
// a checkpoint to adopt either: a peer is verified exactly as the log is.
func TestAPeerServingAnotherGenesisIsNotAdopted(t *testing.T) {
	peerURL, _ := peerServing(t, filepath.Join(vectors(), "served"))
	fake := peertable.NewFake(provenKeys(t)...)
	before, _ := fake.Peers()
	rec := &recorder{}
	a, err := New(Config{Anchor: otherGenesis(t), Fetcher: logclient.Dir(t.TempDir()),
		Device: fake, Mode: reconcile.Owner, Emit: rec.emit,
		Peers: func() []string { return []string{peerURL} },
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err == nil {
		t.Fatal("a peer's log for another genesis was adopted")
	}
	after, _ := fake.Peers()
	if len(after) != len(before) {
		t.Fatalf("the table went from %d peers to %d", len(before), len(after))
	}
	kinds := rec.kinds()
	if kinds[AdoptedFromPeer] != 0 || kinds[PeerRefused] == 0 {
		t.Errorf("the peer should have been refused, not adopted: %v", kinds)
	}
}
