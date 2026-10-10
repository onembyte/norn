package agent

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
)

// The fork every test here proves: the fixture log against a branch that
// shares its first forkAt entries, so the common prefix is forkAt.
const forkAt = 40

// frozenNode is a node of the given mode holding the fixture log, its
// interface already carrying what that head proves, and the forked branch
// ready to serve.
func frozenNode(t *testing.T, mode reconcile.Mode, stateDir string) (*Agent, *peertable.Fake, string, *recorder) {
	t.Helper()
	real, _, entries := writableLog(t)
	rec := &recorder{}
	fake := peertable.NewFake()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: fake, Mode: mode,
		RunDir: t.TempDir(), StateDir: stateDir, Emit: rec.emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if mode != reconcile.Owner {
		// Only owner installs; give the others the same table to guard.
		peers, _ := a.desired(a.held(), peertable.Key{})
		fake.Inject(peers...)
	}
	a.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, forkAt))
	return a, fake, real, rec
}

// wantFrozen is §11 rule 3 computed independently of the agent: the keys
// proven at forkAt and at the held head.
func wantFrozen(t *testing.T, a *Agent) map[peertable.Key]bool {
	t.Helper()
	held := a.held()
	atHead := provenKeysIn(t, held.State, held)
	atSplit := provenKeysIn(t, replay.Replay(a.replayAnchor(), held.Served[:forkAt]), held)
	want := map[peertable.Key]bool{}
	for key := range atHead {
		if _, ok := atSplit[key]; ok {
			want[key] = true
		}
	}
	return want
}

func tableKeys(t *testing.T, fake *peertable.Fake) map[peertable.Key]bool {
	t.Helper()
	peers, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	out := map[peertable.Key]bool{}
	for _, peer := range peers {
		out[peer.Key] = true
	}
	return out
}

func sameKeys(a, b map[peertable.Key]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if !b[key] {
			return false
		}
	}
	return true
}

// D-072 (a): the node that catches the fork shrinks its table to the frozen
// set in the same cycle, and says what it is doing.
func TestAForkShrinksTheTableToTheFrozenSet(t *testing.T) {
	a, fake, _, rec := frozenNode(t, reconcile.Owner, t.TempDir())
	before := tableKeys(t, fake)
	want := wantFrozen(t, a)
	if len(want) >= len(before) {
		t.Fatalf("the fixture's split keeps %d of %d peers; a test of shrinking needs one removed", len(want), len(before))
	}
	if err := a.Once(); err == nil {
		t.Fatal("a forked log was accepted")
	}
	if got := tableKeys(t, fake); !sameKeys(got, want) {
		t.Errorf("after the fork the table holds %d peers, the frozen set is %d", len(got), len(want))
	}
	if !strings.Contains(forkMessages(rec), "common prefix") {
		t.Errorf("the FORK alarm does not say what the node keeps enforcing: %s", forkMessages(rec))
	}
}

// SEC-021, the reason D-072 (a) exists: a frozen watchdog used to stop
// evicting. Now it keeps evicting against the frozen set -- a key the control
// plane adds afterwards, and a device enrolled after the split that comes
// back, both go.
func TestAFrozenWatchdogStillEvicts(t *testing.T) {
	a, fake, _, _ := frozenNode(t, reconcile.Watchdog, t.TempDir())
	want := wantFrozen(t, a)
	var afterSplit peertable.Peer
	for _, peer := range func() []peertable.Peer { p, _ := fake.Peers(); return p }() {
		if !want[peer.Key] {
			afterSplit = peer
		}
	}
	if afterSplit.Key == (peertable.Key{}) {
		t.Fatal("no peer on the interface was enrolled after the split")
	}
	_ = a.Once() // the fork is proved
	fake.Inject(rogue(t), afterSplit)
	_ = a.Once() // frozen
	got := tableKeys(t, fake)
	if got[rogue(t).Key] {
		t.Error("a frozen watchdog left a key the control plane added after the freeze")
	}
	if got[afterSplit.Key] {
		t.Error("a frozen watchdog left a device enrolled after the split")
	}
	if !sameKeys(got, want) {
		t.Errorf("the frozen watchdog holds %d peers, the frozen set is %d", len(got), len(want))
	}
}

// "It MUST never grow": a frozen node removes peers and never installs one,
// even one the frozen set holds, if the interface has lost it.
func TestAFrozenNodeAddsNothing(t *testing.T) {
	a, fake, _, _ := frozenNode(t, reconcile.Owner, t.TempDir())
	_ = a.Once()
	if err := fake.Replace(nil); err != nil {
		t.Fatal(err)
	}
	_ = a.Once()
	if got := tableKeys(t, fake); len(got) != 0 {
		t.Errorf("a frozen node installed %d peers on an emptied interface", len(got))
	}
}

// The restart reaches the same set from what it kept: the evidence's split
// and its own branch, restored from the mirror.
func TestTheFrozenSetSurvivesARestart(t *testing.T) {
	stateDir := t.TempDir()
	a, fake, real, _ := frozenNode(t, reconcile.Owner, stateDir)
	want := wantFrozen(t, a)
	_ = a.Once()

	// The interface comes back from the reboot with the old table.
	peers, _ := a.desired(a.held(), peertable.Key{})
	rebooted := peertable.NewFake(peers...)
	restarted := rebootable(t, real, t.TempDir(), stateDir, rebooted, &recorder{})
	if !restarted.Frozen() {
		t.Fatal("the restart forgot the freeze")
	}
	_ = restarted.Once()
	if got := tableKeys(t, rebooted); !sameKeys(got, want) {
		t.Errorf("after a restart the table holds %d peers, the frozen set is %d", len(got), len(want))
	}
	_ = fake
}

// A freeze with no split to stand behind -- a marker filed when the evidence
// could not be -- fails closed.
func TestAFreezeWithNoKnownSplitFailsClosed(t *testing.T) {
	stateDir := t.TempDir()
	a, _, real, _ := frozenNode(t, reconcile.Owner, t.TempDir())
	if _, err := a.freezeWithoutEvidence("the evidence could not be written in this test"); err != nil {
		t.Fatal(err)
	}
	peers, _ := a.desired(a.held(), peertable.Key{})
	device := peertable.NewFake(peers...)
	_ = stateDir
	rec := &recorder{}
	restarted := rebootable(t, real, t.TempDir(), a.stateDir(), device, rec)
	if !restarted.Frozen() {
		t.Fatal("a freeze marker was not honoured")
	}
	_ = restarted.Once()
	if got := tableKeys(t, device); len(got) != 0 {
		t.Errorf("a node with no common prefix kept %d peers; it fails closed", len(got))
	}
	if !strings.Contains(frozenMessage(rec), "fail") {
		t.Errorf("the FROZEN alarm does not say the node is failing closed: %s", frozenMessage(rec))
	}
}

// Observe reports the frozen set and writes nothing.
func TestAFrozenObserverWritesNothing(t *testing.T) {
	a, fake, _, _ := frozenNode(t, reconcile.Observe, t.TempDir())
	writes := fake.Writes()
	_ = a.Once()
	_ = a.Once()
	if fake.Writes() != writes {
		t.Errorf("a frozen observer wrote to the interface %d times", fake.Writes()-writes)
	}
}

// The bystander: a node that learns of the fork from a peer's evidence holds
// one branch, takes the split from the file, and shrinks as the detector did.
func TestABystanderShrinksToTheFrozenSet(t *testing.T) {
	real, _, entries := writableLog(t)
	peerEvidence := t.TempDir()
	writeEvidenceFor(t, peerEvidence, real, entries)
	peer := httptest.NewServer(gossip.Handler(real, peerEvidence))
	t.Cleanup(peer.Close)

	probe := newAgent(t, reconcile.Owner, real, peertable.NewFake(), &recorder{})
	if err := probe.Once(); err != nil {
		t.Fatal(err)
	}
	peers, _ := probe.desired(probe.held(), peertable.Key{})
	fake := peertable.NewFake(peers...)
	want := wantFrozen(t, probe)

	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: fake,
		Mode: reconcile.Owner, RunDir: t.TempDir(), Emit: (&recorder{}).emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:  func() time.Duration { return 0 },
		Peers: func() []string { return []string{peer.URL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Once()
	if !a.Frozen() {
		t.Fatal("the node did not freeze on the peer's evidence")
	}
	if got := tableKeys(t, fake); !sameKeys(got, want) {
		t.Errorf("the bystander holds %d peers, the frozen set is %d", len(got), len(want))
	}
}
