package agent

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
)

// freshNode is an owner-mode node with no state at all -- a first start, or
// one whose state directory was lost -- whose log is logDir and whose one
// gossip peer is wherever peerURL points when a round runs.
func freshNode(t *testing.T, logDir string, peerURL *string, mono *time.Duration,
	rec *recorder) (*Agent, *peertable.Fake) {
	t.Helper()
	fake := peertable.NewFake()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(logDir), Device: fake,
		Mode: reconcile.Owner, RunDir: t.TempDir(), StateDir: t.TempDir(), Emit: rec.emit,
		Now:         func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(*mono) },
		Mono:        func() time.Duration { return *mono },
		Peers:       func() []string { return []string{*peerURL} },
		GossipEvery: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, fake
}

// D-071 (c). A node with no held head has nothing to compare its first head
// against, so §10 cannot catch a fork for it: the first head verified at any
// size, was enforced at once, and met a peer only at T_g. A log showing this
// node a branch -- cosigned, as A9 allows, by 2k−N colluding witnesses -- had
// it enforcing the attacker's branch for a round and then freezing on it. The
// peer that holds the real log is asked in the same cycle, before anything is
// enforced, and the fork is proven with the table still untouched.
func TestAFreshNodeWhosePeerHoldsTheOtherBranchFreezesBeforeEnforcing(t *testing.T) {
	real, _, entries := writableLog(t)
	branch := forkedLog(t, entries, 40)
	peer := httptest.NewServer(gossip.Handler(real, ""))
	t.Cleanup(peer.Close)
	peerURL := peer.URL
	var mono time.Duration
	rec := &recorder{}
	a, fake := freshNode(t, branch, &peerURL, &mono, rec)

	if err := a.Once(); err == nil {
		t.Fatal("a first head contradicted by a peer was accepted")
	}
	if !a.Frozen() || rec.kinds()[Fork] == 0 {
		t.Fatalf("the fork was not proven in the first cycle: %v", rec.kinds())
	}
	if peers, _ := fake.Peers(); len(peers) != 0 {
		t.Errorf("%d peers of the branch were enforced before the peer was asked", len(peers))
	}
	if files, _ := filepath.Glob(filepath.Join(a.stateDir(), ForkDir, "*.evidence")); len(files) != 1 {
		t.Errorf("evidence files = %v, want one", files)
	}
}

// A node must be able to start: alone, or with peers reachable only through
// the tunnel it has yet to configure, no peer answers its first round. It
// enforces, says once that it did so uncorroborated, and keeps asking every
// cycle. When the peer comes up on the other branch -- well inside T_g -- the
// fork is proven against a head this node enforced on the log's word alone,
// and it has no branch it can stand behind: every peer is dropped, as past
// S_hard, rather than freezing on the attacker's choice.
func TestAFreshNodeWithNoPeerAnsweringEnforcesSaysSoAndDropsEverythingWhenTheForkAppears(t *testing.T) {
	real, _, entries := writableLog(t)
	branch := forkedLog(t, entries, 40)
	peer := httptest.NewServer(gossip.Handler(real, ""))
	t.Cleanup(peer.Close)
	// Nobody listens here: a peer behind a tunnel that does not exist yet.
	peerURL := "http://127.0.0.1:1"
	var mono time.Duration
	rec := &recorder{}
	a, fake := freshNode(t, branch, &peerURL, &mono, rec)

	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if peers, _ := fake.Peers(); len(peers) == 0 {
		t.Fatal("a node whose peers cannot be reached must still be able to start")
	}
	if got := rec.kinds()[FirstHeadUncorroborated]; got != 1 {
		t.Fatalf("%s = %d, want it said once", FirstHeadUncorroborated, got)
	}

	// One second later the peer is reachable, and holds the real log.
	peerURL = peer.URL
	mono = time.Second
	if err := a.Once(); err == nil {
		t.Fatal("the fork was not found; the node waited for T_g")
	}
	if !a.Frozen() || rec.kinds()[Fork] == 0 {
		t.Fatalf("no fork proven on the first cycle the peer answered: %v", rec.kinds())
	}
	if peers, _ := fake.Peers(); len(peers) != 0 {
		t.Errorf("%d peers of a branch this node never corroborated survive the proof it was a fork", len(peers))
	}
	var said bool
	for _, e := range rec.events {
		if e.Kind == Fork && strings.Contains(e.Message, "dropped") {
			said = true
		}
	}
	if !said {
		t.Error("the fork alarm should say the peers were dropped, not that the table is unchanged")
	}
	// Frozen is frozen: the next cycle changes nothing and says nothing new.
	mono = 2 * time.Second
	_ = a.Once()
	if got := rec.kinds()[FirstHeadUncorroborated]; got != 1 {
		t.Errorf("%s repeated: %d", FirstHeadUncorroborated, got)
	}
}

// A peer that agrees corroborates the first head, and from then on the node
// asks on T_g like any other -- not on every cycle, which would be r requests
// per poll to peers that already answered.
func TestACorroboratedFirstHeadIsAskedAgainOnlyOnTg(t *testing.T) {
	real, _, _ := writableLog(t)
	url, asked := peerServing(t, real)
	peerURL := url
	var mono time.Duration
	rec := &recorder{}
	a, fake := freshNode(t, real, &peerURL, &mono, rec)

	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if asked() != 1 {
		t.Fatalf("the peer was asked %d times in the first cycle, want once, before enforcing", asked())
	}
	if peers, _ := fake.Peers(); len(peers) == 0 {
		t.Fatal("a corroborated first head was not enforced")
	}
	if rec.kinds()[FirstHeadUncorroborated] != 0 {
		t.Error("a head a peer agreed with was called uncorroborated")
	}
	mono = time.Second
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if asked() != 1 {
		t.Errorf("a corroborated node asked again after one second (%d asks)", asked())
	}
	mono = 30 * time.Second
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if asked() != 2 {
		t.Errorf("after T_g the peer was asked %d times in all, want 2", asked())
	}
}
