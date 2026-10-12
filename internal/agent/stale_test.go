package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/freshness"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlogstore"
)

// `GOSSIP.md` part 5 gives each freshness state a behaviour, and a state with
// no behaviour is a label:
//
//	degraded    keep the proven set; alarm every 5 min
//	hard-stale  the enforcer drops all peers (owner: ReplacePeers []; watchdog: evict all)

// agingAgent runs against a log built now, with a monotonic clock the test
// drives. Hard is set, so hard-stale is reachable -- which it is not on a
// default node, by design.
func agingAgent(t *testing.T, mode reconcile.Mode, mono *time.Duration,
	hard time.Duration) (*Agent, *recorder, *peertable.Fake) {
	t.Helper()
	dir, _, _ := writableLog(t)
	rec := &recorder{}
	fake := peertable.NewFake()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(dir), Device: fake,
		Mode: mode, RunDir: t.TempDir(), Emit: rec.emit, Hard: hard,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(*mono) },
		Mono: func() time.Duration { return *mono },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Adopt once at monotonic zero. A node's *first* sight of a checkpoint is
	// age zero by construction -- it has no history to measure against, and
	// its own clock is not evidence (A11). Freshness is a property of a
	// running node, so every test below starts it running.
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	return a, rec, fake
}

// A daemon polling every minute must not produce a page a minute. The alarm is
// on a five-minute cadence, measured monotonically like everything else here.
func TestDegradedAlarmsOnACadenceNotEveryCycle(t *testing.T) {
	var mono time.Duration
	a, rec, _ := agingAgent(t, reconcile.Observe, &mono, 0)

	// Sixteen minutes is past the fixture log's 900s staleness.
	for i := 0; i < 10; i++ {
		mono = 16*time.Minute + time.Duration(i)*30*time.Second
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
	}
	if got := rec.kinds()[Degraded]; got != 1 {
		t.Errorf("%d degraded alarms in under five minutes, want 1", got)
	}

	// Past the cadence it says so again: a degraded node that went quiet
	// would be indistinguishable from one that recovered.
	mono = 22 * time.Minute
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := rec.kinds()[Degraded]; got != 2 {
		t.Errorf("degraded alarms = %d, want 2 once the cadence has passed", got)
	}
}

// Recovering and degrading again alarms at once. Carrying the suppression
// across a recovery would silence the very transition an operator needs.
//
// This drives the cadence directly rather than through a log, because the
// state it needs -- the same node degraded, recovered and degraded again --
// takes a log that is re-cosigned between cycles, and what is under test here
// is when the alarm fires, not how the state was reached.
func TestRecoveringResetsTheAlarmCadence(t *testing.T) {
	var mono time.Duration
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(servedLog(t)), Device: peertable.NewFake(),
		Mode: reconcile.Observe, Emit: rec.emit,
		Mono: func() time.Duration { return mono },
	})
	if err != nil {
		t.Fatal(err)
	}

	age := 20 * time.Minute
	degraded := proven.Freshness{State: freshness.Degraded, Age: &age}
	fresh := proven.Freshness{State: freshness.Fresh, Age: new(time.Duration)}

	for _, step := range []struct {
		name string
		mono time.Duration
		in   proven.Freshness
		want int
	}{
		{"first degradation alarms", 0, degraded, 1},
		{"a minute later, silent", time.Minute, degraded, 1},
		{"four minutes later, still silent", 4 * time.Minute, degraded, 1},
		{"past the cadence, alarms again", 5 * time.Minute, degraded, 2},
		{"recovered, nothing said here", 6 * time.Minute, fresh, 2},
		{"degrading again alarms at once", 7 * time.Minute, degraded, 3},
	} {
		mono = step.mono
		a.reportFreshness(step.in)
		if got := rec.kinds()[Degraded]; got != step.want {
			t.Errorf("%s: alarms = %d, want %d", step.name, got, step.want)
		}
	}
}

// Degraded keeps the proven set. That is the whole point of the state: the log
// being quiet is not evidence that a peer stopped being proven.
func TestDegradedKeepsThePeerTable(t *testing.T) {
	var mono time.Duration
	a, _, fake := agingAgent(t, reconcile.Owner, &mono, 0)

	before, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(before) == 0 {
		t.Fatal("no peers to keep")
	}

	mono = 20 * time.Minute
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	after, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("degraded dropped peers: %d -> %d", len(before), len(after))
	}
}

// Past S_hard the enforcer drops everything, in both enforcing modes. This is
// a deliberate outage: the node would rather be disconnected than enforce a
// view nobody has vouched for in that long.
func TestHardStaleDropsEveryPeer(t *testing.T) {
	for _, mode := range []reconcile.Mode{reconcile.Owner, reconcile.Watchdog} {
		t.Run(string(mode), func(t *testing.T) {
			var mono time.Duration
			a, rec, fake := agingAgent(t, mode, &mono, time.Hour)

			// Watchdog installs nothing, so give it a table to guard.
			if mode == reconcile.Watchdog {
				fake.Inject(provenKeys(t)...)
			}
			if peers, _ := fake.Peers(); len(peers) == 0 {
				t.Fatal("no peers installed to begin with")
			}

			mono = 2 * time.Hour
			if err := a.Once(); err != nil {
				t.Fatal(err)
			}
			peers, err := fake.Peers()
			if err != nil {
				t.Fatal(err)
			}
			if len(peers) != 0 {
				t.Errorf("%d peers survived hard-stale", len(peers))
			}
			// And it says why, once: an operator left with a dozen
			// UNPROVEN_PEER lines would not know the cause was the clock.
			if got := rec.kinds()[HardStale]; got != 1 {
				t.Errorf("%s alarms = %d, want 1", HardStale, got)
			}
			set, err := proven.Read(filepath.Join(a.cfg.RunDir, proven.FileName))
			if err != nil {
				t.Fatal(err)
			}
			if set.Freshness != freshness.HardStale {
				t.Errorf("freshness = %q, want %q", set.Freshness, freshness.HardStale)
			}
		})
	}
}

// Observe never writes, however stale it gets: a mode that started changing
// the table under a long outage would be the one mode nobody asked to enforce.
func TestHardStaleStillWritesNothingInObserve(t *testing.T) {
	var mono time.Duration
	a, rec, fake := agingAgent(t, reconcile.Observe, &mono, time.Hour)

	fake.Inject(provenKeys(t)...)
	mono = 2 * time.Hour
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if peers, _ := fake.Peers(); len(peers) == 0 {
		t.Error("observe mode emptied the table")
	}
	if got := rec.kinds()[HardStale]; got != 1 {
		t.Errorf("observe must still report hard-stale, got %d", got)
	}
}

// S_hard is opt-in: a node that was never configured for it stays degraded
// forever rather than taking its own network down after a long enough outage.
func TestWithoutSHardANodeNeverGoesHardStale(t *testing.T) {
	var mono time.Duration
	a, rec, fake := agingAgent(t, reconcile.Owner, &mono, 0)

	mono = 30 * 24 * time.Hour // a month
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}

	if peers, _ := fake.Peers(); len(peers) == 0 {
		t.Error("a node with no S_hard configured dropped its peers anyway")
	}
	if got := rec.kinds()[HardStale]; got != 0 {
		t.Errorf("%s fired with S_hard off", HardStale)
	}
}

// A node keeps what it verified, so it has something to serve its peers
// (GOSSIP part 6, full replication). The test that matters is not "files
// appeared" but that what it wrote verifies on its own -- with the log gone.
func TestANodeMirrorsTheLogItVerified(t *testing.T) {
	dir, _, _ := writableLog(t)
	runDir := t.TempDir()
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(dir), Device: peertable.NewFake(),
		Mode: reconcile.Observe, RunDir: runDir, Emit: rec.emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}

	// Verified straight out of the node's own directory, with nothing running.
	doc := anchor(t)
	result, err := logclient.Verify(logclient.Dir(filepath.Join(runDir, proven.MirrorDir)),
		logclient.Anchor{
			Anchor:  replay.FromTrust(doc),
			LogKeys: []string{doc.LogKey}, Policy: doc.Policy,
		})
	if err != nil {
		t.Fatalf("what the node kept does not verify on its own: %v", err)
	}
	if result.Checkpoint.Size == 0 {
		t.Error("the mirror is empty")
	}
}

// Observe mode writes nothing to the interface, but it still mirrors: a node
// that only watched is exactly the node you want serving the mesh, because it
// is the one nobody is worried about.
func TestObserveModeStillMirrors(t *testing.T) {
	dir, _, _ := writableLog(t)
	runDir := t.TempDir()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(dir), Device: peertable.NewFake(),
		Mode: reconcile.Observe, RunDir: runDir, Emit: (&recorder{}).emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(runDir, proven.MirrorDir, "checkpoint")); err != nil {
		t.Errorf("observe mode kept nothing to serve: %v", err)
	}
}

// The check only protects a node that uses it, so the agent must pass the head
// it holds on every cycle. A node that dropped it would accept a correctly
// signed, correctly cosigned view of its own past -- and un-revoke whoever was
// revoked since.
func TestANodeRefusesALogThatWentBackwards(t *testing.T) {
	full, store, entries := writableLog(t)
	rec := &recorder{}
	fake := peertable.NewFake()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: fake,
		Mode: reconcile.Owner, Emit: rec.emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	held, _ := fake.Peers()
	if len(held) == 0 {
		t.Fatal("nothing was enforced to begin with")
	}
	_ = store

	// The same network's log, truncated: every signature and cosignature on it
	// is valid, because it is this log, earlier.
	short := shorterLog(t, entries[:len(entries)/2])
	a.cfg.Fetcher = logclient.Dir(short)

	err = a.Once()
	if err == nil {
		t.Fatal("a node accepted its own log rolled back")
	}
	if rec.kinds()[VerifyFailed] == 0 {
		t.Error("the rollback should have been reported")
	}
	// And the table it was already enforcing is untouched.
	after, _ := fake.Peers()
	if len(after) != len(held) {
		t.Errorf("the peer table changed on a refused checkpoint: %d -> %d",
			len(held), len(after))
	}
}

// shorterLog builds a valid, cosigned log over a prefix of the fixture's
// entries -- the same network, at an earlier size.
func shorterLog(t *testing.T, entries [][]byte) string {
	t.Helper()
	doc := anchor(t)
	dir := t.TempDir()
	store, err := tlogstore.Open(dir, doc.Origin, fixtureKey(t, "logkey"),
		tlogstore.WithCosigner(tlogstore.CosignerFunc(
			cosign.Append(fixtureWitnesses(t), cosign.At(time.Unix(fixtureCosignedAt, 0))))))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// Phase 4's second gate line: "Witness quorum lost -> node refuses the new
// checkpoint, keeps last good, alarms."
//
// The refusal itself is 4.1c's, tested in the verifier. What was never tested
// is the *node's* half: that a checkpoint short of the quorum leaves the peer
// table exactly as it was and says so. A verifier that refuses while the
// daemon quietly enforces anyway would satisfy neither the line nor anybody
// reading it.
func TestAQuorumShortCheckpointKeepsTheTableAndAlarms(t *testing.T) {
	full, _, entries := writableLog(t)
	fake := peertable.NewFake()
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: fake,
		Mode: reconcile.Owner, Emit: rec.emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	held := a.last.Checkpoint
	before, _ := fake.Peers()
	if len(before) == 0 {
		t.Fatal("nothing was enforced to begin with")
	}

	// The witnesses go away: the log grows and only its own signature is on
	// the new head. Everything else about it is perfect.
	a.cfg.Fetcher = logclient.Dir(unwitnessedLog(t, entries))

	if err := a.Once(); err == nil {
		t.Fatal("a checkpoint no quorum cosigned was accepted")
	}
	if rec.kinds()[VerifyFailed] == 0 {
		t.Error("losing the quorum should be alarmed, not absorbed")
	}
	if a.last.Checkpoint != held {
		t.Error("the stored checkpoint moved to one no quorum vouched for")
	}
	after, _ := fake.Peers()
	if len(after) != len(before) {
		t.Errorf("the peer table changed: %d -> %d", len(before), len(after))
	}
}

// unwitnessedLog is the fixture's log grown by one entry, signed by the log
// and cosigned by nobody -- what a network looks like when its witnesses are
// unreachable.
func unwitnessedLog(t *testing.T, entries [][]byte) string {
	t.Helper()
	doc := anchor(t)
	dir := t.TempDir()
	store, err := tlogstore.Open(dir, doc.Origin, fixtureKey(t, "logkey"))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
