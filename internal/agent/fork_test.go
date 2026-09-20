package agent

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/reconcile"
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
	rules, err := policy.Parse(doc.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forkevidence.Check(ev, doc.Origin, doc.LogKey, rules.Keys()); err != nil {
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
