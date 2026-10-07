package agent

import (
	"crypto/ed25519"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

// SPEC §11, all four duties:
//
//  1. write both checkpoints and the failed proof to fork/<unix>.evidence
//  2. keep the stored checkpoint and proven set unchanged
//  3. raise a FORK alarm
//  4. refuse every later checkpoint not consistent with the stored one --
//     forever, until an operator resets with a new trust file
//
// The fourth is the one that has to survive a restart, and the one a node
// would otherwise quietly drop: a daemon that forgot it had caught its log
// equivocating would go back to trusting it on the next reboot.

// forkedLog builds a second branch of the fixture's network: the same genesis,
// diverging after `common` entries, signed and cosigned exactly as correctly
// as the real one.
func forkedLog(t *testing.T, entries [][]byte, common int) string {
	t.Helper()
	doc := anchor(t)
	branch := append([][]byte(nil), entries[:common]...)
	// One entry the real log never had, so the trees diverge from here.
	env := &entry.Envelope{
		V: entry.Version, T: "revoke", Net: doc.Net, TS: 1_760_600_000,
		Body: map[string]any{"device_id": "nas", "reason": "the fork's own idea"},
	}
	for _, name := range []string{"signer1", "signer2"} {
		if err := entry.Sign(env, fixtureKey(t, name), "signer"); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	branch = append(branch, raw)

	dir := t.TempDir()
	store, err := tlogstore.Open(dir, doc.Origin, fixtureKey(t, "logkey"),
		tlogstore.WithCosigner(tlogstore.CosignerFunc(
			cosign.Append(fixtureWitnesses(t), cosign.At(time.Unix(fixtureCosignedAt, 0))))))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range branch {
		if _, err := store.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestAForkFreezesTheNodeAndLeavesEvidence(t *testing.T) {
	real, _, entries := writableLog(t)
	runDir := t.TempDir()
	fake := peertable.NewFake()
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: fake,
		Mode: reconcile.Owner, RunDir: runDir, Emit: rec.emit,
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

	// The log starts serving a different history.
	a.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, 40))
	if err := a.Once(); err == nil {
		t.Fatal("a forked log was accepted")
	}

	// 3. the alarm
	if rec.kinds()[Fork] != 1 {
		t.Errorf("events = %v, want one %s", rec.kinds(), Fork)
	}
	// 2. the stored checkpoint and the peer table are untouched
	if a.last.Checkpoint != held {
		t.Error("the stored checkpoint moved after a fork")
	}
	after, _ := fake.Peers()
	if len(after) != len(before) {
		t.Errorf("the peer table changed on a fork: %d -> %d", len(before), len(after))
	}
	// 1. the evidence, and it must convince somebody else
	files, err := filepath.Glob(filepath.Join(runDir, ForkDir, "*.evidence"))
	if err != nil || len(files) != 1 {
		t.Fatalf("evidence files = %v (%v)", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	ev, err := forkevidence.Parse(raw)
	if err != nil {
		t.Fatalf("the evidence a node wrote does not parse: %v", err)
	}
	doc := anchor(t)
	if _, err := forkevidence.Check(ev, doc.Origin, doc.LogKey, doc.Policy); err != nil {
		t.Fatalf("the evidence a node wrote does not prove a fork: %v", err)
	}
}

// Duty 4: a frozen node refuses everything afterwards, including the log it
// was happily using a moment ago. "Forever" is the word §11 uses, and a node
// that un-froze the moment the log looked sensible again would be trusting a
// log it has proof equivocated.
func TestAFrozenNodeRefusesEvenTheGoodLog(t *testing.T) {
	real, _, entries := writableLog(t)
	runDir := t.TempDir()
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: peertable.NewFake(),
		Mode: reconcile.Owner, RunDir: runDir, Emit: rec.emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	a.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, 40))
	_ = a.Once()

	// The original log comes back, exactly as it was.
	a.cfg.Fetcher = logclient.Dir(real)
	if err := a.Once(); err == nil {
		t.Fatal("a frozen node went back to trusting a log it has proof equivocated")
	}
	if rec.kinds()[Frozen] == 0 {
		t.Errorf("a frozen node should say why it is refusing: %v", rec.kinds())
	}
}

// And the freeze outlives the process. A daemon that forgot on restart would
// be a daemon an attacker reboots.
func TestTheFreezeSurvivesARestart(t *testing.T) {
	real, _, entries := writableLog(t)
	runDir := t.TempDir()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: peertable.NewFake(),
		Mode: reconcile.Owner, RunDir: runDir, Emit: (&recorder{}).emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	a.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, 40))
	_ = a.Once()

	// A fresh process, same run directory, same anchor.
	rec := &recorder{}
	restarted, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: peertable.NewFake(),
		Mode: reconcile.Owner, RunDir: runDir, Emit: rec.emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Once(); err == nil {
		t.Fatal("a restarted node forgot it had caught its log forking")
	}
	if rec.kinds()[Frozen] == 0 {
		t.Errorf("the restarted node should say it is frozen: %v", rec.kinds())
	}
}

// The reset §11 allows: "until an operator explicitly resets with a new trust
// file". A different anchor is a different network to this node, so evidence
// about the old one does not freeze it -- and the evidence is kept, because it
// is still evidence.
func TestANewTrustFileClearsTheFreeze(t *testing.T) {
	real, _, entries := writableLog(t)
	runDir := t.TempDir()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: peertable.NewFake(),
		Mode: reconcile.Owner, RunDir: runDir, Emit: (&recorder{}).emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	a.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, 40))
	_ = a.Once()

	// The operator provisions a new anchor: same keys, a different network.
	fresh := freshAnchor(t)
	restarted, err := New(Config{
		Anchor: fresh, Fetcher: logclient.Dir(real), Device: peertable.NewFake(),
		Mode: reconcile.Observe, RunDir: runDir, Emit: (&recorder{}).emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Frozen() {
		t.Error("a new trust file did not clear the freeze; §11's only way out " +
			"would be unavailable")
	}
	// The evidence is still on disk: it is what an operator takes to the
	// witness operators.
	files, _ := filepath.Glob(filepath.Join(runDir, ForkDir, "*.evidence"))
	if len(files) != 1 {
		t.Errorf("evidence files = %v; a reset must not destroy the evidence", files)
	}
}

// freshAnchor is the fixture's anchor under a different network id, standing
// in for the new trust file an operator provisions after a fork.
func freshAnchor(t *testing.T) *trust.Trust {
	t.Helper()
	doc := *anchor(t)
	net := append([]byte(nil), doc.Net...)
	net[0] ^= 0xff
	doc.Net = net
	origin, err := trust.OriginFor(net)
	if err != nil {
		t.Fatal(err)
	}
	doc.Origin = origin

	// §9.1 binds the log key's note name to the origin, so the new anchor
	// carries the same key under its own name -- which is what provisioning a
	// fresh trust file for the same operator actually looks like.
	verifier, err := note.ParseVerifierKey(doc.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	renamed := note.VerifierKey(origin, ed25519.PublicKey(verifier.Public))
	doc.Policy = strings.Replace(doc.Policy, doc.LogKey, renamed, 1)
	doc.Policy = strings.Replace(doc.Policy, "log "+anchor(t).Origin, "log "+origin, 1)
	doc.LogKey = renamed
	return &doc
}

// Phase 4's first gate line: "two log instances presenting divergent
// checkpoints to two nodes -> **detected via gossip**".
//
// That is the scenario gossip exists for. A node whose log is fine learns from
// a *peer* that a second history is circulating -- and a peer serving a forked
// branch must be treated as what it is, not filed away as one neighbour being
// unreachable. §11 does not care which source the second history arrived from.
func TestAForkedPeerIsAForkNotABrokenNeighbour(t *testing.T) {
	real, _, entries := writableLog(t)
	forked := forkedLog(t, entries, 40)
	runDir := t.TempDir()
	rec := &recorder{}
	fake := peertable.NewFake()

	peer := httptest.NewServer(gossip.Handler(forked, ""))
	t.Cleanup(peer.Close)

	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: fake,
		Mode: reconcile.Owner, RunDir: runDir, Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:  func() time.Duration { return 0 },
		Peers: func() []string { return []string{peer.URL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	before, _ := fake.Peers()

	// The log goes quiet, so the node asks its peers -- and one of them is
	// serving the other history.
	a.cfg.Fetcher = logclient.Dir(t.TempDir())
	_ = a.Once()

	if rec.kinds()[Fork] == 0 {
		t.Fatalf("a peer serving a second history was not reported as a fork: %v",
			rec.kinds())
	}
	if !a.Frozen() {
		t.Error("the node did not freeze on a fork it learned from a peer")
	}
	files, _ := filepath.Glob(filepath.Join(runDir, ForkDir, "*.evidence"))
	if len(files) != 1 {
		t.Errorf("evidence files = %v; a fork learned from a peer is still a fork", files)
	}
	after, _ := fake.Peers()
	if len(after) != len(before) {
		t.Errorf("the peer table changed on a fork: %d -> %d", len(before), len(after))
	}
}

func TestHealthyButSplitLogFindsTheOtherBranchByCheckpointGossip(t *testing.T) {
	real, _, entries := writableLog(t)
	forked := forkedLog(t, entries, 40)
	peer := httptest.NewServer(gossip.Handler(forked, ""))
	t.Cleanup(peer.Close)
	var mono time.Duration
	runDir := t.TempDir()
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: peertable.NewFake(),
		Mode: reconcile.Owner, RunDir: runDir, Emit: rec.emit,
		Now:         func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(mono) },
		Mono:        func() time.Duration { return mono },
		Peers:       func() []string { return []string{peer.URL} },
		GossipEvery: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	held := a.last.Checkpoint
	mono = 30 * time.Second
	_ = a.Once()
	if rec.kinds()[Fork] == 0 || !a.Frozen() {
		t.Fatalf("healthy but split log did not detect its peer's branch: %v", rec.kinds())
	}
	files, _ := filepath.Glob(filepath.Join(runDir, ForkDir, "*.evidence"))
	if len(files) != 1 {
		t.Errorf("evidence files = %v, want one", files)
	}
	if a.last.Checkpoint != held {
		t.Error("a peer fork changed the stored checkpoint")
	}
}

// T1b: "a node that never saw the second branch freezes via peer evidence".
//
// Evidence polling runs independently from checkpoint gossip. Node3 may miss
// the conflicting branch in its sampled checkpoint round but can still learn
// the proof from a peer; both paths run while its direct log is healthy.
func TestANodeFreezesOnEvidenceFromAPeer(t *testing.T) {
	real, _, entries := writableLog(t)
	runDir := t.TempDir()

	// A peer that has already proved the fork, and is serving the evidence.
	peerEvidence := t.TempDir()
	writeEvidenceFor(t, peerEvidence, real, entries)
	peer := httptest.NewServer(gossip.Handler(real, peerEvidence))
	t.Cleanup(peer.Close)

	rec := &recorder{}
	fake := peertable.NewFake()
	a, err := New(Config{
		// This node's log is perfectly healthy and consistent.
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: fake,
		Mode: reconcile.Owner, RunDir: runDir, Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:  func() time.Duration { return 0 },
		Peers: func() []string { return []string{peer.URL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Freezing is reported as an error from the cycle, which is what it is.
	if err := a.Once(); err == nil {
		t.Fatal("a node with a healthy log did not freeze on a peer's proof that " +
			"its log has forked; nothing else would ever have told it")
	}
	if !a.Frozen() {
		t.Fatal("the node did not freeze")
	}
	if rec.kinds()[Fork] == 0 {
		t.Errorf("freezing on somebody else's evidence should be alarmed: %v", rec.kinds())
	}
	// §11 duty 2 holds however the fork was learned -- and a node that learns
	// of a fork before it ever enforced anything enforces nothing at all.
	after, _ := fake.Peers()
	if len(after) != 0 {
		t.Errorf("%d peers were installed from a history proved to be a fork", len(after))
	}
	// And the node keeps a copy, so it can pass it on.
	files, _ := filepath.Glob(filepath.Join(runDir, ForkDir, "*.evidence"))
	if len(files) != 1 {
		t.Errorf("evidence files = %v; a node that froze on evidence should hold it", files)
	}
}

// A peer serving rubbish, or evidence that proves nothing, must not be able to
// freeze a network. Evidence is believed because it is *checked*, and the same
// check a stranger would run is the one that runs here.
func TestFabricatedEvidenceFromAPeerIsIgnored(t *testing.T) {
	real, _, _ := writableLog(t)
	bogus := t.TempDir()
	if err := os.WriteFile(filepath.Join(bogus, "1760000000.evidence"),
		[]byte("not evidence of anything"), 0o644); err != nil {
		t.Fatal(err)
	}
	peer := httptest.NewServer(gossip.Handler(real, bogus))
	t.Cleanup(peer.Close)

	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: peertable.NewFake(),
		Mode: reconcile.Owner, RunDir: t.TempDir(), Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:  func() time.Duration { return 0 },
		Peers: func() []string { return []string{peer.URL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if a.Frozen() {
		t.Fatal("a peer froze this node with bytes that prove nothing; anybody on " +
			"the tunnel could take the network down")
	}
}

// writeEvidenceFor builds genuine evidence for the fixture's network and puts
// it where a peer would serve it from.
func writeEvidenceFor(t *testing.T, dir, logDir string, entries [][]byte) {
	t.Helper()
	held, err := logclient.Verify(logclient.Dir(logDir), logclient.Anchor{
		Anchor:  replay.Anchor{Net: anchor(t).Net, GenesisHash: anchor(t).GenesisHash},
		LogKeys: []string{anchor(t).LogKey}, Policy: anchor(t).Policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := logclient.Verify(logclient.Dir(forkedLog(t, entries, 40)), logclient.Anchor{
		Anchor:  replay.Anchor{Net: anchor(t).Net, GenesisHash: anchor(t).GenesisHash},
		LogKeys: []string{anchor(t).LogKey}, Policy: anchor(t).Policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := forkevidence.Build(held.Tree, held.SignedCheckpoint,
		other.SignedCheckpoint, other.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Policy = anchor(t).Policy
	raw, err := evidence.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1760000000.evidence"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}
