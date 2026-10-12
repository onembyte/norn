package agent

import (
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
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlogstore"

	"net/http/httptest"
)

// forkedLogUnder is forkedLog signed by the named log key and cosigned by the
// first `witnesses` of the fixture's three.
func forkedLogUnder(t *testing.T, entries [][]byte, common int, key string, witnesses int) string {
	t.Helper()
	doc := anchor(t)
	branch := append([][]byte(nil), entries[:common]...)
	env := &entry.Envelope{
		Prev: replay.Replay(replay.FromTrust(doc), branch).Previous("revoke", "nas"), V: entry.Version, T: "revoke", Net: doc.Net, TS: 1_760_600_000,
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
	dir := t.TempDir()
	store, err := tlogstore.Open(dir, doc.Origin, fixtureKey(t, key),
		tlogstore.WithCosigner(tlogstore.CosignerFunc(
			cosign.Append(fixtureWitnesses(t)[:witnesses], cosign.At(time.Unix(fixtureCosignedAt, 0))))))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range append(branch, raw) {
		if _, err := store.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// SEC-005 (b). A node verifies its log under the trust file's key and the keys
// its roots published (§9.4, D-020); after an in-log rotation the head it
// holds is signed by the new key. Its evidence was then checked under the
// trust file's key alone -- so a node that followed its log correctly and
// caught it forking built evidence its own self-check refused, filed a marker
// instead, and after a restart said its proof "would not convince anybody
// else". §11.1 says both checkpoints are verified per §10, and §10 accepts the
// published keys.
func TestEvidenceAfterALogKeyRotationIsFiledAndReloadsClean(t *testing.T) {
	dir, store, entries := writableLog(t)
	runDir := t.TempDir()
	rec := &recorder{}
	a := restartable(t, dir, runDir, peertable.NewFake(), rec)
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	reHead(t, dir, store, "logkey2", 3)
	if err := a.Once(); err != nil {
		t.Fatalf("the node did not follow the rotation, so nothing here is tested: %v", err)
	}

	a.cfg.Fetcher = logclient.Dir(forkedLogUnder(t, entries, 40, "logkey2", 3))
	if err := a.Once(); err == nil || !a.Frozen() {
		t.Fatalf("the fork was not proven: %v", err)
	}
	evidence, _ := filepath.Glob(filepath.Join(runDir, ForkDir, "*.evidence"))
	markers, _ := filepath.Glob(filepath.Join(runDir, ForkDir, "*.frozen"))
	if len(evidence) != 1 || len(markers) != 0 {
		t.Fatalf("evidence %v, markers %v; a node that proved a fork under its learned "+
			"key should file evidence, not a marker", evidence, markers)
	}

	restarted := restartable(t, dir, runDir, peertable.NewFake(), &recorder{})
	if !restarted.Frozen() {
		t.Fatal("the freeze did not survive the restart")
	}
	if restarted.frozenNote != "" {
		t.Errorf("the node's own evidence was doubted after a restart: %s", restarted.frozenNote)
	}
}

// SEC-005 (c). The roots can raise the witness quorum in the log, and a node
// that has replayed the raise refuses heads short of it (D-020). Evidence from
// a peer was still checked under the trust file's policy, so two witnesses
// that a raised three-of-three quorum would not believe were enough to freeze
// the node -- the weaker rule deciding the most drastic thing a node does.
func TestPeerEvidenceIsCheckedUnderTheRaisedQuorum(t *testing.T) {
	real, store, entries := writableLog(t)

	// Both branches cosigned by only two of the three witnesses.
	thin := t.TempDir()
	if err := os.CopyFS(thin, os.DirFS(real)); err != nil {
		t.Fatal(err)
	}
	reHead(t, thin, store, "logkey", 2)
	held, err := logclient.Verify(logclient.Dir(thin), trustOnlyAnchor(t))
	if err != nil {
		t.Fatalf("the two-witness head should verify under the trust file's 2-of-3: %v", err)
	}
	other, err := logclient.Verify(logclient.Dir(forkedLogUnder(t, entries, 40, "logkey", 2)), trustOnlyAnchor(t))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := forkevidence.Build(held.Tree, other.Tree, held.SignedCheckpoint, other.SignedCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	ev.Policy = anchor(t).Policy
	raw, err := ev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	served := t.TempDir()
	if err := os.WriteFile(filepath.Join(served, "1760000000.evidence"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	peer := httptest.NewServer(gossip.Handler(real, served))
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
	_ = a.Once()
	if a.Frozen() {
		t.Fatal("two witnesses froze a node whose roots require three")
	}
	refused := false
	for _, e := range rec.events {
		if e.Kind == PeerRefused && strings.Contains(e.Message, "proves nothing") {
			refused = true
		}
	}
	if !refused {
		t.Errorf("the short-quorum evidence should be refused out loud: %v", rec.kinds())
	}
}

// trustOnlyAnchor is the fixture's trust file and nothing learned.
func trustOnlyAnchor(t *testing.T) logclient.Anchor {
	t.Helper()
	doc := anchor(t)
	a := (&Agent{cfg: Config{Anchor: doc}}).anchorUnder(nil)
	return a
}
