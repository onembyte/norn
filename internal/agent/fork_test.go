package agent

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
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
	// 2. the stored checkpoint is untouched, and the table holds the frozen
	// set: what both branches proved at their common prefix and this node's
	// head still proves -- D-072 (a), §11 rule 3, where it used to be left
	// exactly as it was
	if a.last.Checkpoint != held {
		t.Error("the stored checkpoint moved after a fork")
	}
	if got := tableKeys(t, fake); !sameKeys(got, wantFrozen(t, a)) {
		t.Errorf("the peer table after a fork holds %d of %d peers, not the frozen set",
			len(got), len(before))
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
	if _, err := forkevidence.Check(ev, doc.Origin, []string{doc.LogKey}, doc.Policy); err != nil {
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

	// The peer agrees with the log while the node starts, so the node's first
	// head is corroborated (D-071 c) and this is a node with history, as the
	// name says: one that then learns of the fork from a neighbour.
	agreeing := httptest.NewServer(gossip.Handler(real, ""))
	t.Cleanup(agreeing.Close)
	peer := httptest.NewServer(gossip.Handler(forked, ""))
	t.Cleanup(peer.Close)
	peerURL := agreeing.URL

	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: fake,
		Mode: reconcile.Owner, RunDir: runDir, Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:  func() time.Duration { return 0 },
		Peers: func() []string { return []string{peerURL} },
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
	peerURL = peer.URL
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
	// A fork learned from a peer leaves the same frozen set (§11 rule 3).
	if got := tableKeys(t, fake); !sameKeys(got, wantFrozen(t, a)) {
		t.Errorf("the peer table after a fork holds %d of %d peers, not the frozen set",
			len(got), len(before))
	}
}

func TestHealthyButSplitLogFindsTheOtherBranchByCheckpointGossip(t *testing.T) {
	real, _, entries := writableLog(t)
	forked := forkedLog(t, entries, 40)
	// The peer agrees at first, so the node's first head is corroborated
	// (D-071 c; a fresh node whose peer disagrees is firsthead_test.go's
	// case). The split appears at the next gossip round.
	agreeing := httptest.NewServer(gossip.Handler(real, ""))
	t.Cleanup(agreeing.Close)
	peer := httptest.NewServer(gossip.Handler(forked, ""))
	t.Cleanup(peer.Close)
	peerURL := agreeing.URL
	var mono time.Duration
	runDir := t.TempDir()
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(real), Device: peertable.NewFake(),
		Mode: reconcile.Owner, RunDir: runDir, Emit: rec.emit,
		Now:         func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(mono) },
		Mono:        func() time.Duration { return mono },
		Peers:       func() []string { return []string{peerURL} },
		GossipEvery: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	held := a.last.Checkpoint
	peerURL = peer.URL
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
		Anchor:  replay.FromTrust(anchor(t)),
		LogKeys: []string{anchor(t).LogKey}, Policy: anchor(t).Policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := logclient.Verify(logclient.Dir(forkedLog(t, entries, 40)), logclient.Anchor{
		Anchor:  replay.FromTrust(anchor(t)),
		LogKeys: []string{anchor(t).LogKey}, Policy: anchor(t).Policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := forkevidence.Build(held.Tree, other.Tree, held.SignedCheckpoint,
		other.SignedCheckpoint)
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

// evidenceAgent is a node with a state directory and a clock that does not
// move, so everything it files is filed in the same second.
func evidenceAgent(t *testing.T) (*Agent, string) {
	t.Helper()
	dir, _, _ := writableLog(t)
	stateDir := t.TempDir()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(dir), Device: peertable.NewFake(),
		StateDir: stateDir, Emit: (&recorder{}).emit,
		Now: func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, filepath.Join(stateDir, ForkDir)
}

// Evidence was filed under the second it was written in, so a second piece
// filed in the same second truncated the first -- and the first may be the
// only proof an operator has, or evidence about the network this node ran
// before a reset (§11), which is kept for exactly that reason. A file already
// there is never rewritten: a later piece takes the next free second, which
// keeps §11's `<unix>.evidence` names and their chronological order.
func TestEvidenceFiledInTheSameSecondIsNotOverwritten(t *testing.T) {
	a, forkDir := evidenceAgent(t)
	first, err := a.storeEvidence([]byte("the first proof"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.storeEvidence([]byte("the second proof"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("two different pieces of evidence were filed under one name, %s", first)
	}
	if got, _ := os.ReadFile(first); string(got) != "the first proof" {
		t.Errorf("the first piece of evidence now holds %q", got)
	}
	want := filepath.Join(forkDir, fmt.Sprintf("%d.evidence", fixtureCosignedAt+1))
	if second != want {
		t.Errorf("the second piece was filed as %s, want the next second, %s", second, want)
	}
}

// The same evidence filed twice is one file, and a file that is already
// there -- even one torn by a crash under the code before this -- is left
// exactly as it is rather than refilled in place.
func TestEvidenceNeverRewritesAFile(t *testing.T) {
	a, forkDir := evidenceAgent(t)
	torn := filepath.Join(forkDir, fmt.Sprintf("%d.evidence", fixtureCosignedAt))
	if err := os.MkdirAll(forkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(torn, []byte("a torn pr"), 0o644); err != nil {
		t.Fatal(err)
	}

	path, err := a.storeEvidence([]byte("a whole proof"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(torn); string(got) != "a torn pr" {
		t.Errorf("a file already there was rewritten; it holds %q", got)
	}
	again, err := a.storeEvidence([]byte("a whole proof"))
	if err != nil || again != path {
		t.Errorf("the same evidence was filed as %s, then %s (%v)", path, again, err)
	}
	if entries, _ := os.ReadDir(forkDir); len(entries) != 2 {
		t.Errorf("the fork directory holds %v, want the torn file and one proof", entries)
	}
}

// SEC-005 (a). A fork is detected at the smaller of the two sizes, and
// evidence was always built from this node's own tree -- which cannot speak
// for a size it never reached. So a log that forked and then grew past this
// node's head raised FORK, built nothing, froze in memory only, and a restart
// unfroze it: the natural shape of a growing log defeated the freeze. The
// node has just fetched the whole served branch, which is exactly what §11.1
// means by `held`, so the roles swap and the evidence is written.
func TestAForkOnTheLongerBranchStillLeavesEvidence(t *testing.T) {
	real, _, entries := writableLog(t)
	stateDir := t.TempDir()
	rec := &recorder{}
	a := rebootable(t, forkedLog(t, entries, 15), t.TempDir(), stateDir, peertable.NewFake(), rec)
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	a.cfg.Fetcher = logclient.Dir(real) // the same network's log, forked below 16 and far longer

	var fork *logclient.ForkError
	if err := a.Once(); !errors.As(err, &fork) {
		t.Fatalf("the longer branch was not detected as a fork: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(stateDir, ForkDir, "*.evidence"))
	if len(files) != 1 {
		t.Fatalf("evidence files = %v, want one; the FORK events say: %s", files, forkMessages(rec))
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := forkevidence.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc := anchor(t)
	finding, err := forkevidence.Check(evidence, doc.Origin, []string{doc.LogKey}, doc.Policy)
	if err != nil {
		t.Fatalf("the evidence this node wrote does not prove a fork to a stranger: %v", err)
	}
	if finding.Size != 16 {
		t.Errorf("the fork is proved at size %d, want 16, this node's own size", finding.Size)
	}

	restarted := rebootable(t, real, t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
	if !restarted.Frozen() {
		t.Fatal("a restart unfroze a node that had proved its log forked")
	}
}

func forkMessages(rec *recorder) string {
	var out []string
	for _, e := range rec.events {
		if e.Kind == Fork {
			out = append(out, e.Message)
		}
	}
	return strings.Join(out, " | ")
}

// SEC-005 (a), the remainder: a node that proved a fork but could not file
// evidence froze in memory only, and a restart unfroze it. The node follows
// a log-key rotation (D-020), which once prevented evidence from being built
// (SEC-005 b, fixed later). Now the evidence write is made to fail instead:
// the freeze must not depend on the file.
func TestAFreezeSurvivesARestartEvenWhenEvidenceCannotBeBuilt(t *testing.T) {
	dir, store, entries := writableLog(t)
	stateDir := t.TempDir()
	rec := &recorder{}
	a := rebootable(t, dir, t.TempDir(), stateDir, peertable.NewFake(), rec)
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	reHead(t, dir, store, "logkey2", 3)
	if err := a.Once(); err != nil {
		t.Fatalf("the node did not follow the rotation, so nothing here is tested: %v", err)
	}

	a.writeEvidenceFile = func(string, []byte, fs.FileMode) error {
		return errors.New("evidence write failed in this test")
	}
	a.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, 40))
	var fork *logclient.ForkError
	if err := a.Once(); !errors.As(err, &fork) {
		t.Fatalf("the forked branch was not detected: %v", err)
	}
	if files, err := filepath.Glob(filepath.Join(stateDir, ForkDir, "*.evidence")); err != nil || len(files) != 0 {
		t.Fatalf("evidence files = %v (%v), want none after the failed write", files, err)
	}
	if !strings.Contains(forkMessages(rec), "could not be written") {
		t.Fatalf("the FORK event should say the evidence could not be written: %s", forkMessages(rec))
	}

	restarted := rebootable(t, dir, t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
	if !restarted.Frozen() {
		t.Fatal("a restart unfroze a node that had proved its log forked and could not file evidence")
	}
}

// The marker on its own: written for this network, honoured at the next
// start; written for another network, ignored -- §11's reset by a new trust
// file must still work.
func TestAFreezeMarkerIsHonouredOnlyForItsOwnNetwork(t *testing.T) {
	dir, _, _ := writableLog(t)
	stateDir := t.TempDir()
	a := rebootable(t, dir, t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
	path, err := a.freezeWithoutEvidence("the evidence could not be built in this test")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(path) != ".frozen" || filepath.Dir(path) != filepath.Join(stateDir, ForkDir) {
		t.Errorf("the marker was filed as %s", path)
	}
	if !rebootable(t, dir, t.TempDir(), stateDir, peertable.NewFake(), &recorder{}).Frozen() {
		t.Error("a freeze marker for this network was not honoured")
	}
	other, err := New(Config{Anchor: freshAnchor(t), Fetcher: logclient.Dir(dir),
		Device: peertable.NewFake(), StateDir: stateDir, Emit: (&recorder{}).emit})
	if err != nil {
		t.Fatal(err)
	}
	if other.Frozen() {
		t.Error("a freeze marker for another network froze this node")
	}
}

// rotatedAnchor stands for an operator's mistake: the same network with a
// rotated log key and a matching policy log line (§9.1). D-082 (2) requires
// every trust file for a network to name its initial key and policy; this
// file replays the log to another state and cannot remedy a compromise.
// It is still the same network, so it must not clear a freeze (§11).
func rotatedAnchor(t *testing.T) *trust.Trust {
	t.Helper()
	doc := *anchor(t)
	rotated := note.VerifierKey(doc.Origin, fixtureKey(t, "logkey2").Public().(ed25519.PublicKey))
	doc.Policy = strings.Replace(doc.Policy, doc.LogKey, rotated, 1)
	doc.LogKey = rotated
	return &doc
}

func frozenMessage(rec *recorder) string {
	for _, e := range rec.events {
		if e.Kind == Frozen {
			return e.Message
		}
	}
	return ""
}

// SEC-005 (a), last part. A freeze file found at start is checked, as a
// stranger would check it. But a file that no longer proves the fork is not
// a reason to run: it was written by this node when it had proof, and the
// usual way it stops verifying is a rotated trust file (SEC-005 b) -- so the
// node stays frozen and the alarm says the file would not convince anybody
// else, which is what the operator has to know before carrying it anywhere.
func TestEvidenceThatNoLongerVerifiesStillFreezesAndSaysSo(t *testing.T) {
	real, _, entries := writableLog(t)
	stateDir := t.TempDir()
	a := rebootable(t, real, t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	a.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, 40))
	_ = a.Once()
	if files, _ := filepath.Glob(filepath.Join(stateDir, ForkDir, "*.evidence")); len(files) != 1 {
		t.Fatalf("evidence files = %v, want one", files)
	}

	rec := &recorder{}
	restarted, err := New(Config{Anchor: rotatedAnchor(t), Fetcher: logclient.Dir(real),
		Device: peertable.NewFake(), StateDir: stateDir, Emit: rec.emit,
		Now: func() time.Time { return time.Unix(fixtureCosignedAt, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.Frozen() {
		t.Fatal("a rotated trust file for the same network unfroze the node")
	}
	_ = restarted.Once()
	if msg := frozenMessage(rec); !strings.Contains(msg, "does not verify") {
		t.Errorf("the alarm should say the evidence no longer verifies under this trust "+
			"file: %q", msg)
	}
}

// And evidence that does verify is reported as proof, with no doubt attached.
func TestEvidenceThatVerifiesCarriesNoDoubt(t *testing.T) {
	real, _, entries := writableLog(t)
	stateDir := t.TempDir()
	a := rebootable(t, real, t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	a.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, 40))
	_ = a.Once()

	rec := &recorder{}
	restarted := rebootable(t, real, t.TempDir(), stateDir, peertable.NewFake(), rec)
	_ = restarted.Once()
	msg := frozenMessage(rec)
	if msg == "" || strings.Contains(msg, "does not verify") {
		t.Errorf("verifying evidence should be reported as proof, plainly: %q", msg)
	}
}

// A marker has no proof in it, only a reason; the alarm carries the reason.
func TestAFreezeMarkersReasonReachesTheAlarm(t *testing.T) {
	dir, _, _ := writableLog(t)
	stateDir := t.TempDir()
	a := rebootable(t, dir, t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
	if _, err := a.freezeWithoutEvidence("the witnesses' keys had rotated under us"); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	restarted := rebootable(t, dir, t.TempDir(), stateDir, peertable.NewFake(), rec)
	_ = restarted.Once()
	if msg := frozenMessage(rec); !strings.Contains(msg, "the witnesses' keys had rotated under us") {
		t.Errorf("the alarm should carry the marker's reason: %q", msg)
	}
}
