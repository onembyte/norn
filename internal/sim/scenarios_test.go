package sim

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/agent"
	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/freshness"
	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/monitor"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

// These are GOSSIP.md §8's T1, T1b, T2, T4 and T6. Simulated time proves
// ordering and bounds in the code; it does not replace the lab's wall-clock
// measurements. No sleeps, listeners or verifier substitutes are involved.
const (
	cosignedAt = 1_760_003_600
	tg         = 10 * time.Second
	staleness  = time.Minute
)

func TestT1BothNodesProveTheSplitViewAndFreeze(t *testing.T) {
	t.Log("Simulated time proves code ordering and bounds; it does not replace the lab's wall-clock measurements.")
	a, b, m := splitView(t)
	start, mark := m.Elapsed, len(m.Events)
	before := []heldState{held(t, m.Nodes[0]), held(t, m.Nodes[1])}
	latencies := map[string]time.Duration{}
	for m.Elapsed-start < 2*tg {
		forkCycle(t, m, tg, 0, 1)
		for i, node := range m.Nodes[:2] {
			if node.Agent.Frozen() {
				if _, seen := latencies[node.ID]; !seen {
					checkSplitEvidence(t, a, b, nodeEvidence(t, node))
					if !hasEvent(m.Events[mark:], node.ID, agent.Fork, "a quorum of witnesses cosigned both") {
						t.Fatalf("%s froze without its own FORK alarm", node.ID)
					}
					latencies[node.ID] = m.Elapsed - start
				}
				if !reflect.DeepEqual(before[i], held(t, node)) {
					t.Fatalf("%s changed its held state on the fork", node.ID)
				}
			}
		}
	}
	for i, node := range m.Nodes[:2] {
		latency, ok := latencies[node.ID]
		if !ok {
			t.Fatalf("%s did not freeze within 2*T_g", node.ID)
		}
		// Each node must make its own accusation, so evidence polling cannot
		// hide a missing comparison in this scenario.
		if !hasEvent(m.Events[mark:], node.ID, agent.Fork, "a quorum of witnesses cosigned both") ||
			!hasEvent(m.Events[mark:], node.ID, agent.Frozen, "refusing every checkpoint") {
			t.Fatalf("%s did not emit FORK and FROZEN_BY_FORK within 2*T_g", node.ID)
		}
		raw := nodeEvidence(t, node)
		ev := checkSplitEvidence(t, a, b, raw)
		if ev.Held != before[i].Checkpoint {
			t.Fatalf("%s did not accuse from its own held branch", node.ID)
		}
		t.Logf("T1 %s evidence, freeze and FORK latency: %s simulated (bound %s); FROZEN_BY_FORK by %s", node.ID, latency, 2*tg, m.Elapsed-start)
	}

	// The existing monitor.Watcher collects evidence from the real gossip
	// endpoint. Its fork-evidence alert reports receipt, not verification;
	// the independent §11.1 check above proves that these bytes are sound.
	// Its next round is at 3*T_g, with dispatch in memory and no socket.
	watcher := monitor.New(a.doc, monitor.Default())
	watcher.Now = func() time.Time { return m.Nodes[0].Wall }
	// Even a new, consistent extension of either original branch must not
	// lift the freeze or republish the proven set under this trust file.
	a.params(t, map[string]any{"staleness": uint64(120)})
	b.params(t, map[string]any{"staleness": uint64(121)})
	forkCycle(t, m, tg, 0, 1)
	var alerts []monitor.Alert
	func() {
		previous := gossip.SetTransport(m)
		defer gossip.SetTransport(previous)
		alerts = watcher.Round(logclient.Dir(a.dir), []monitor.Node{
			{Name: m.Nodes[0].ID, URL: "http://10.77.0.1:8099"},
			{Name: m.Nodes[1].ID, URL: "http://10.77.0.2:8099"},
		})
	}()
	for i, node := range m.Nodes[:2] {
		received := false
		for _, alert := range alerts {
			if alert.Rule == "fork-evidence" && alert.Level == monitor.Critical && alert.Subject == node.ID {
				received = true
			}
		}
		if !received || m.Elapsed-start > 3*tg {
			t.Fatalf("monitor did not receive %s's evidence within 3*T_g: %+v", node.ID, alerts)
		}
		if !node.Agent.Frozen() || !reflect.DeepEqual(before[i], held(t, node)) {
			t.Fatalf("%s resumed after a consistent extension", node.ID)
		}
	}
	t.Logf("T1 monitor evidence receipt latency: %s simulated (bound %s)", m.Elapsed-start, 3*tg)
}

func TestT1bANodeSeeingOnlyBranchAFreezesFromPeerEvidence(t *testing.T) {
	t.Log("Simulated time proves code ordering and bounds; it does not replace the lab's wall-clock measurements.")
	a, b, m := splitView(t)
	node1, node3 := m.Nodes[0], m.Nodes[2]
	before := held(t, node3)
	start, mark := m.Elapsed, len(m.Events)

	// Node3 can reach only node1, whose mirror holds A; its direct source
	// also stays on A. Node2's B checkpoint is unreachable throughout this
	// scenario. Evidence contains B's signed head, but checkpoint gossip
	// must never provide it to node3 as a candidate for adoption.
	delete(m.handlers, "http://10.77.0.2:8099")
	// Produce evidence through a real agent's direct-log comparison. This
	// keeps the propagation control independent of T1's peer comparison:
	// disabling that comparison must not erase T1b's source of evidence.
	node1.Gossip = false
	node1.Log.Source = logclient.Dir(b.dir)
	forkCycle(t, m, 0, 0)
	if !node1.Agent.Frozen() || !hasEvent(m.Events[mark:], node1.ID, agent.Fork, "a quorum of witnesses cosigned both") {
		t.Fatal("node1 did not produce evidence from the direct split view")
	}
	sourceEvidence := nodeEvidence(t, node1)
	ev := checkSplitEvidence(t, a, b, sourceEvidence)
	if held(t, node1).Checkpoint != ev.Held || ev.Held != before.Checkpoint {
		t.Fatal("node1's checkpoint endpoint no longer serves branch A")
	}
	var latency time.Duration
	for m.Elapsed-start < 3*tg {
		forkCycle(t, m, tg, 2)
		if node3.Agent.Frozen() {
			latency = m.Elapsed - start
			break
		}
	}
	if !node3.Agent.Frozen() {
		t.Fatal("node3 did not freeze via peer evidence within 3*T_g")
	}
	if !hasEvent(m.Events[mark:], node3.ID, agent.Fork, "peer http://10.77.0.1:8099 proved") {
		t.Fatal("node3 did not attribute its FORK alarm to node1's evidence")
	}
	if !bytes.Equal(sourceEvidence, nodeEvidence(t, node3)) {
		t.Fatal("node3 did not persist the evidence it received")
	}
	checkSplitEvidence(t, a, b, nodeEvidence(t, node3))
	if !reflect.DeepEqual(before, held(t, node3)) {
		t.Fatal("node3 changed its proven set, checkpoint or peer table on peer evidence")
	}
	t.Logf("T1b node3 evidence, freeze and FORK latency: %s simulated (bound %s)", latency, 3*tg)

	// A healthy extension on A, and time beyond the freshness threshold,
	// cannot undo §11's permanent freeze or trigger further enforcement.
	a.params(t, map[string]any{"staleness": uint64(120)})
	forkCycle(t, m, tg, 2)
	if !hasEvent(m.Events[mark:], node3.ID, agent.Frozen, "refusing every checkpoint") {
		t.Fatal("node3 did not report FROZEN_BY_FORK on its next cycle")
	}
	t.Logf("T1b node3 FROZEN_BY_FORK latency: %s simulated", m.Elapsed-start)
	forkCycle(t, m, staleness+tg, 2)
	if !node3.Agent.Frozen() || !reflect.DeepEqual(before, held(t, node3)) || !bytes.Equal(sourceEvidence, nodeEvidence(t, node3)) {
		t.Fatal("node3 resumed or changed state after freezing on peer evidence")
	}
}

// splitView first corroborates a common prefix, so §11's unchanged-table
// contract applies rather than D-071's uncorroborated-first-head drop. The
// split is delivered between gossip rounds, and each node verifies its own
// log's complete tree before the next exchange exposes the disagreement.
func splitView(t *testing.T) (*fixture, *fixture, *Mesh) {
	t.Helper()
	a := newFixture(t)
	// The second tlogstore replays the same fixture prefix and uses the same
	// log and witness keys. Neither checkpoint nor verifier is substituted.
	b := newFixture(t)
	prefix := a.store.Checkpoint()
	if b.store.Checkpoint() != prefix {
		t.Fatal("the branches do not start from the same prefix")
	}
	m := a.mesh(t)
	goodCycle(t, m, 0)
	goodCycle(t, m, 0)
	a.params(t, map[string]any{"staleness": uint64(60)})
	b.params(t, map[string]any{"staleness": uint64(61)})
	acp, bcp := a.store.Checkpoint(), b.store.Checkpoint()
	if acp.Size != prefix.Size+1 || bcp.Size != acp.Size || acp.Root == bcp.Root {
		t.Fatal("the log did not produce equal-size branches with different final entries")
	}
	rules, err := policy.Parse(a.doc.Policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, branch := range []*fixture{a, b} {
		result, err := logclient.Verify(logclient.Dir(branch.dir), branch.anchor())
		if err != nil {
			t.Fatalf("branch does not verify on its own: %v", err)
		}
		root, err := result.Tree.HeadAt(prefix.Size)
		if err != nil || root != prefix.Root {
			t.Fatalf("branch lost the common prefix: %v", err)
		}
		sigs, err := cosign.Verify(result.SignedCheckpoint, rules.Keys())
		names := map[string]bool{}
		for _, sig := range sigs {
			names[sig.Name] = true
		}
		if err != nil || len(names) != 3 {
			t.Fatalf("branch must have all three genuine witness cosignatures: %v (%d witnesses)", err, len(names))
		}
	}
	m.Nodes[1].Log.Source = logclient.Dir(b.dir)
	for _, node := range m.Nodes {
		node.Gossip = false
	}
	goodCycle(t, m, time.Second)
	for i, node := range m.Nodes {
		want := acp
		if i == 1 {
			want = bcp
		}
		if got := view(t, node).Checkpoint; got.Size != want.Size || got.Root != hex.EncodeToString(want.Root[:]) {
			t.Fatalf("%s did not adopt its assigned branch: %+v", node.ID, got)
		}
		node.Gossip = true
	}
	return a, b, m
}

func forkCycle(t *testing.T, m *Mesh, delta time.Duration, indices ...int) {
	t.Helper()
	for i, err := range m.Cycle(delta, indices...) {
		node := m.Nodes[indices[i]]
		// Direct detection returns the verifier's typed error; peer detection
		// and later frozen cycles return the agent's refusal instead.
		var fork *logclient.ForkError
		if err != nil && (!node.Agent.Frozen() || (!errors.As(err, &fork) && !strings.Contains(err.Error(), "fork"))) {
			t.Fatalf("%s at %s: unexpected error: %v", node.ID, m.Elapsed, err)
		}
	}
}

func nodeEvidence(t *testing.T, node *Node) []byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(node.Dir, agent.ForkDir, "*.evidence"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("%s evidence files = %v: %v", node.ID, paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func checkSplitEvidence(t *testing.T, a, b *fixture, raw []byte) *forkevidence.Evidence {
	t.Helper()
	ev, err := forkevidence.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := forkevidence.Check(ev, a.doc.Origin, []string{a.doc.LogKey}, a.doc.Policy)
	if err != nil {
		t.Fatalf("written evidence does not prove a fork: %v", err)
	}
	acp, bcp := a.store.Checkpoint(), b.store.Checkpoint()
	if finding.Size != acp.Size || bcp.Size != acp.Size || len(ev.Proof) != 0 ||
		!((finding.Held == acp.Root && finding.Claimed == bcp.Root) || (finding.Held == bcp.Root && finding.Claimed == acp.Root)) ||
		!bytes.Equal(ev.HeldRoot, finding.Held[:]) {
		t.Fatalf("evidence does not name the two branches at their shared size: %+v", finding)
	}
	return ev
}

func TestT2PeersCarryTheNewHeadWhenTheLogFreezes(t *testing.T) {
	t.Log("Simulated time proves code ordering and bounds; it does not replace the lab's wall-clock measurements.")
	// Run the same schedule twice: event order and simulated timestamps must
	// agree, including which peer supplied the head.
	var first []Event
	for run := 0; run < 2; run++ {
		f := newFixture(t)
		m := f.mesh(t)
		goodCycle(t, m, 0)
		n := f.store.Checkpoint().Size
		f.params(t, map[string]any{"staleness": uint64(staleness / time.Second)})
		goodCycle(t, m, 0, 0)
		if got := view(t, m.Nodes[0]).Checkpoint.Size; got != n+1 {
			t.Fatalf("node1 has %d, want N+1=%d", got, n+1)
		}
		for _, node := range m.Nodes[1:] {
			if got := view(t, node).Checkpoint.Size; got != n {
				t.Fatalf("%s already has %d before the freeze, want N=%d", node.ID, got, n)
			}
		}
		start := m.Elapsed
		mark := len(m.Events)
		for _, node := range m.Nodes {
			node.Log.Stalled = true
		}
		adopted := map[string]time.Duration{}
		for m.Elapsed-start < 2*tg {
			// Poll the lagging nodes first in each round, then the holder.
			// A failed fetch is permitted while they catch up; adoption
			// and freshness, rather than reachability, are the bound.
			for _, err := range m.Cycle(tg, 1, 2, 0) {
				if code, _ := refusal.CodeOf(err); err != nil && code != refusal.Unserved {
					t.Fatalf("unexpected freeze error: %v", err)
				}
			}
			for _, node := range m.Nodes {
				if node.Agent.Freshness() != freshness.Fresh {
					t.Fatalf("%s went %s during the freeze", node.ID, node.Agent.Freshness())
				}
			}
			for _, node := range m.Nodes[1:] {
				if view(t, node).Checkpoint.Size == n+1 {
					if _, seen := adopted[node.ID]; !seen {
						adopted[node.ID] = m.Elapsed - start
					}
				}
			}
		}
		for _, node := range m.Nodes[1:] {
			latency, ok := adopted[node.ID]
			if !ok {
				t.Fatalf("%s did not adopt N+1 through gossip within 2*T_g", node.ID)
			}
			if !hasEvent(m.Events[mark:], node.ID, agent.AdoptedFromPeer, fmt.Sprintf("took size %d", n+1)) {
				t.Fatalf("%s did not report peer adoption", node.ID)
			}
			t.Logf("T2 %s adoption latency: %s simulated (bound %s)", node.ID, latency, 2*tg)
		}
		for _, event := range m.Events {
			if event.Kind == agent.Degraded {
				t.Fatalf("T2 degraded: %+v", event)
			}
		}
		if run == 0 {
			first = m.Events
		} else if !reflect.DeepEqual(first, m.Events) {
			t.Fatal("the same T2 schedule produced different events")
		}
	}
}

func TestT4EveryNodeRefusesACosignedReplayWithoutChangingState(t *testing.T) {
	t.Log("Simulated time proves code ordering and bounds; it does not replace the lab's wall-clock measurements.")
	f := newFixture(t)
	// This frozen prefix includes the routing params. The later revocation
	// makes accepting it harmful, not just a different checkpoint number.
	old := f.snapshot(t)
	for i := 0; i < 4; i++ {
		f.params(t, map[string]any{"staleness": uint64(staleness / time.Second)})
	}
	f.append(t, "revoke", map[string]any{"device_id": "pi-cam", "reason": "lost"}, "signer", "signer1", "signer2")
	m := f.mesh(t)
	goodCycle(t, m, 0)
	n := f.store.Checkpoint().Size
	older, err := logclient.Verify(logclient.Dir(old), f.anchor())
	if err != nil || older.Checkpoint.Size != n-5 {
		t.Fatalf("replay is not a valid N-5 head: %v", err)
	}
	before := make([]heldState, len(m.Nodes))
	for i, node := range m.Nodes {
		before[i] = held(t, node)
		if len(view(t, node).Devices) != 2 {
			t.Fatal("the revocation did not take effect")
		}
		node.Log.Source = logclient.Dir(old)
		// A successful fallback would mask the direct error. Every node already
		// holds N; this step isolates what happens when only the replay answers.
		node.Gossip = false
	}
	mark := len(m.Events)
	start := m.Elapsed
	errs := m.Cycle(time.Second)
	if len(errs) != len(m.Nodes) {
		t.Fatal("the scheduler did not run every node")
	}
	for i, node := range m.Nodes {
		if code, _ := refusal.CodeOf(errs[i]); code != refusal.Rollback {
			t.Errorf("%s replay refusal = %v, want rollback", node.ID, errs[i])
		}
		if !hasEvent(m.Events[mark:], node.ID, agent.VerifyFailed, "a log does not shrink") {
			t.Errorf("%s did not report the rollback", node.ID)
		}
		if !reflect.DeepEqual(before[i], held(t, node)) {
			t.Errorf("%s changed state on replay", node.ID)
		}
	}
	t.Logf("T4 all-node replay refusal latency: %s simulated", m.Elapsed-start)
}

func TestT6NodesHoldDegradeAndRecoverWhenWitnessQuorumReturns(t *testing.T) {
	t.Log("Simulated time proves code ordering and bounds; it does not replace the lab's wall-clock measurements.")
	f := newFixture(t)
	m := f.mesh(t)
	goodCycle(t, m, 0)
	before := make([]heldState, len(m.Nodes))
	for i, node := range m.Nodes {
		before[i] = held(t, node)
	}
	goodSize := f.store.Checkpoint().Size
	// Only one witness now cosigns a genuinely newer head. The source still
	// serves all its files; this is quorum loss, not a fetch failure.
	f.witnesses = 1
	f.params(t, map[string]any{"staleness": uint64(staleness / time.Second)})
	if _, err := logclient.Verify(logclient.Dir(f.dir), f.anchor()); err == nil {
		t.Fatal("one witness unexpectedly satisfied the policy")
	} else if code, _ := refusal.CodeOf(err); code != refusal.Quorum {
		t.Fatalf("want quorum refusal, got %v", err)
	}
	start := m.Elapsed
	mark := len(m.Events)
	for m.Elapsed-start <= staleness {
		for _, err := range m.Cycle(tg) {
			// Gossip may supply the held head and turn this cycle into a
			// success. With no answering peer, the direct quorum refusal
			// is expected and must leave enforcement just as it was.
			if code, _ := refusal.CodeOf(err); err != nil && code != refusal.Quorum {
				t.Fatalf("unexpected quorum-loss error: %v", err)
			}
		}
		for i, node := range m.Nodes {
			now := held(t, node)
			if now.Checkpoint != before[i].Checkpoint || !reflect.DeepEqual(now.Peers, before[i].Peers) || !reflect.DeepEqual(now.Devices, before[i].Devices) || now.Writes != before[i].Writes {
				t.Fatalf("%s did not hold the last good head and peer table", node.ID)
			}
			want := freshness.Fresh
			if m.Elapsed-start > staleness {
				want = freshness.Degraded
			}
			if node.Agent.Freshness() != want {
				t.Fatalf("%s at %s: freshness=%s, want %s", node.ID, m.Elapsed-start, node.Agent.Freshness(), want)
			}
			if view(t, node).Checkpoint.Size != goodSize {
				t.Fatalf("%s adopted the under-quorum head", node.ID)
			}
		}
	}
	for _, node := range m.Nodes {
		if !hasEvent(m.Events[mark:], node.ID, agent.Degraded, "keeping the peer table") {
			t.Fatalf("%s degraded silently", node.ID)
		}
	}
	t.Logf("T6 all-node degraded latency: %s simulated (S=%s; fresh at S)", m.Elapsed-start, staleness)
	f.witnesses = 3
	f.at = time.Unix(cosignedAt, 0).Add(m.Elapsed + tg)
	if err := f.store.Republish(); err != nil {
		t.Fatal(err)
	}
	recovered := m.Elapsed
	goodCycle(t, m, tg)
	for i, node := range m.Nodes {
		if node.Agent.Freshness() != freshness.Fresh || view(t, node).Checkpoint.Size != goodSize+1 {
			t.Fatalf("%s did not recover to a fresh, quorum-backed head", node.ID)
		}
		if !reflect.DeepEqual(before[i].Peers, held(t, node).Peers) {
			t.Fatalf("%s changed peers during recovery", node.ID)
		}
	}
	t.Logf("T6 all-node recovery latency: %s simulated", m.Elapsed-recovered)
}

// The fixture follows agent/gate_test.go's writableLog and appendRevoke, and
// routes_test.go's appendParams. A short prefix retains the original 2-of-3
// policy and three active devices; later vector policy rotations are unrelated
// to these scenarios. Keys are read from the existing fixture, never copied.
type fixture struct {
	dir       string
	doc       *trust.Trust
	store     *tlogstore.Store
	witnesses int
	at        time.Time
}

func vectors() string { return filepath.Join("..", "..", "testdata", "vectors") }

func key(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Ed25519 map[string]struct{ Seed string } `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(keys.Ed25519[name].Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("no fixture seed for %q", name)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{dir: t.TempDir(), doc: doc, witnesses: 3, at: time.Unix(cosignedAt, 0)}
	var signers []cosign.Signer
	for _, name := range []string{"pi", "vps", "friend"} {
		signers = append(signers, cosign.Signer{Name: "norn-witness/" + name, Key: key(t, "witness-"+name)})
	}
	f.store, err = tlogstore.Open(f.dir, doc.Origin, key(t, "logkey"),
		tlogstore.WithCosigner(tlogstore.CosignerFunc(func(signed string) (string, error) {
			return cosign.Append(signers[:f.witnesses], cosign.At(f.at))(signed)
		})))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"0-genesis", "1-enroll-nas", "2-enroll-laptop", "3-enroll-pi-cam"} {
		raw, err := os.ReadFile(filepath.Join(vectors(), "log", name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	f.params(t, map[string]any{"routes": "advisory", "staleness": uint64(staleness / time.Second)})
	return f
}

func (f *fixture) append(t *testing.T, typ string, body map[string]any, role string, names ...string) {
	t.Helper()
	after := uint64(f.store.Checkpoint().Size)
	env := &entry.Envelope{V: entry.Version, T: typ, Net: f.doc.Net, TS: cosignedAt, After: &after, Body: body}
	for _, name := range names {
		if err := entry.Sign(env, key(t, name), role); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Append(raw); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) params(t *testing.T, body map[string]any) {
	t.Helper()
	f.append(t, "params", body, "root", "root1", "root2", "root3")
}

func (f *fixture) anchor() logclient.Anchor {
	return logclient.Anchor{Anchor: replay.Anchor{Net: f.doc.Net, GenesisHash: f.doc.GenesisHash}, Origin: f.doc.Origin, LogKeys: []string{f.doc.LogKey}, Policy: f.doc.Policy}
}

func (f *fixture) snapshot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(f.dir)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func (f *fixture) mesh(t *testing.T) *Mesh {
	t.Helper()
	result, err := logclient.Verify(logclient.Dir(f.dir), f.anchor())
	if err != nil {
		t.Fatal(err)
	}
	var ids []Identity
	for i, id := range []string{"nas", "laptop", "pi-cam"} {
		raw, err := hex.DecodeString(result.State.Devices[id].WgPk)
		if err != nil {
			t.Fatal(err)
		}
		k, err := peertable.KeyFromBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, Identity{ID: id, Key: k, Prefix: netip.MustParsePrefix(fmt.Sprintf("10.77.0.%d/32", i+1))})
	}
	m, err := New(t.TempDir(), f.doc, logclient.Dir(f.dir), ids, time.Unix(cosignedAt, 0), tg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func goodCycle(t *testing.T, m *Mesh, delta time.Duration, indices ...int) {
	t.Helper()
	for _, err := range m.Cycle(delta, indices...) {
		if err != nil {
			t.Fatalf("cycle at %s: %v", m.Elapsed, err)
		}
	}
	for _, node := range m.Nodes {
		if node.Agent.Freshness() == freshness.Unknown {
			t.Fatalf("%s: the scheduler left the agent uninitialized", node.ID)
		}
	}
}

func view(t *testing.T, n *Node) proven.Set {
	t.Helper()
	set, err := proven.Read(filepath.Join(n.Dir, proven.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

type heldState struct {
	Checkpoint string
	Published  string
	Freshness  string
	Devices    []proven.Device
	Peers      []peertable.Peer
	Writes     int
}

func held(t *testing.T, n *Node) heldState {
	t.Helper()
	cp, err := os.ReadFile(filepath.Join(n.Dir, proven.MirrorDir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	// Replay must leave the whole published view untouched, including its
	// checkpoint and freshness metadata, not just the active device list.
	published, err := os.ReadFile(filepath.Join(n.Dir, proven.FileName))
	if err != nil {
		t.Fatal(err)
	}
	peers, err := n.Device.Peers()
	if err != nil {
		t.Fatal(err)
	}
	return heldState{Checkpoint: string(cp), Published: string(published), Freshness: n.Agent.Freshness(),
		Devices: view(t, n).Devices, Peers: peers, Writes: n.Device.Writes()}
}

func hasEvent(events []Event, node, kind, message string) bool {
	for _, e := range events {
		if e.Node == node && e.Kind == kind && strings.Contains(e.Message, message) {
			return true
		}
	}
	return false
}
