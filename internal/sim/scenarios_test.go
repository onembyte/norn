package sim

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/agent"
	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/enrollreq"
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

// These are GOSSIP.md §8's T1, T1b, T2, T4, T5, T6 and T7. Simulated time
// proves ordering and bounds in the code; it does not replace the lab's
// wall-clock measurements. No sleeps, listeners or verifier substitutes are
// involved.
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
				wantFrozenTable(t, node, before[i], beforeSplitPeers(before[i].Peers))
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
		t.Logf("T1 %s evidence, freeze, table shrink and FORK latency: %s simulated (bound %s); FROZEN_BY_FORK by %s", node.ID, latency, 2*tg, m.Elapsed-start)
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
		wantFrozenTable(t, node, before[i], beforeSplitPeers(before[i].Peers))
	}
	t.Logf("T1 monitor evidence receipt latency: %s simulated (bound %s)", m.Elapsed-start, 3*tg)

	// Even a peer proven at the prefix must not be reinstalled after the
	// interface loses it. This distinguishes never growing from merely
	// refusing the new branch's authorization state.
	for _, node := range m.Nodes[:2] {
		if err := node.Device.Replace(nil); err != nil {
			t.Fatal(err)
		}
	}
	forkCycle(t, m, tg, 0, 1)
	for i, node := range m.Nodes[:2] {
		wantFrozenTable(t, node, before[i], nil)
	}
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
	wantPeers := beforeSplitPeers(before.Peers)
	wantFrozenTable(t, node3, before, wantPeers)
	t.Logf("T1b node3 evidence, freeze, table shrink and FORK latency: %s simulated (bound %s)", latency, 3*tg)

	// A healthy extension on A, and time beyond the freshness threshold,
	// cannot undo §11's permanent freeze. A pre-split peer removed from
	// the interface meanwhile must not be installed again either.
	wantPeers = wantPeers[1:]
	if err := node3.Device.Replace(wantPeers); err != nil {
		t.Fatal(err)
	}
	a.params(t, map[string]any{"staleness": uint64(120)})
	forkCycle(t, m, tg, 2)
	if !hasEvent(m.Events[mark:], node3.ID, agent.Frozen, "refusing every checkpoint") {
		t.Fatal("node3 did not report FROZEN_BY_FORK on its next cycle")
	}
	t.Logf("T1b node3 FROZEN_BY_FORK latency: %s simulated", m.Elapsed-start)
	forkCycle(t, m, staleness+tg, 2)
	wantFrozenTable(t, node3, before, wantPeers)
	if !bytes.Equal(sourceEvidence, nodeEvidence(t, node3)) {
		t.Fatal("node3 changed its evidence after freezing")
	}
}

func TestT1cANodeWhoseBranchDoesNotReachTheSplitFailsClosed(t *testing.T) {
	t.Log("Simulated time proves code ordering and bounds; it does not replace the lab's wall-clock measurements.")
	a, b := newFixture(t), newFixture(t)
	m := a.mesh(t)
	goodCycle(t, m, 0)
	goodCycle(t, m, 0)
	node1, node3 := m.Nodes[0], m.Nodes[2]
	before := held(t, node3)
	if len(before.Peers) != 2 {
		t.Fatal("the bystander must enforce peers before learning of the fork")
	}
	node3.Log.Source = logclient.Dir(a.snapshot(t))
	// Both signed branches share a real entry beyond node3's held head.
	// The evidence is valid, but node3 cannot establish that prefix locally.
	a.params(t, map[string]any{"staleness": uint64(120)})
	b.params(t, map[string]any{"staleness": uint64(120)})
	split := a.store.Checkpoint().Size
	a.enrollAfterSplit(t)
	b.params(t, map[string]any{"staleness": uint64(121)})
	node1.Gossip = false
	goodCycle(t, m, time.Second, 0)
	node1.Log.Source = logclient.Dir(b.dir)
	forkCycle(t, m, 0, 0)
	raw := nodeEvidence(t, node1)
	ev := checkSplitEvidence(t, a, b, raw)
	if int64(ev.Split) != split || split <= view(t, node3).Checkpoint.Size {
		t.Fatal("the evidence does not claim a split beyond the bystander's held head")
	}
	delete(m.handlers, "http://10.77.0.2:8099")
	// The detector's checkpoint is unavailable while its evidence remains
	// reachable. Otherwise checkpoint gossip first advances the bystander
	// to A, where it can establish the split before it reads the evidence.
	detector := m.handlers["http://10.77.0.1:8099"]
	m.handlers["http://10.77.0.1:8099"] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/checkpoint") {
			http.Error(w, "checkpoint unavailable", http.StatusServiceUnavailable)
			return
		}
		detector.ServeHTTP(w, r)
	})
	mark := len(m.Events)
	forkCycle(t, m, tg, 2)
	wantFrozenTable(t, node3, before, nil)
	if !hasEvent(m.Events[mark:], node3.ID, agent.Fork, "peer http://10.77.0.1:8099 proved") ||
		!bytes.Equal(raw, nodeEvidence(t, node3)) {
		t.Fatal("the bystander did not freeze on the detector's verified evidence")
	}
	forkCycle(t, m, tg, 2)
	why := fmt.Sprintf("fails closed and drops every peer: this node's branch does not reach the split at %d entries", split)
	if !hasEvent(m.Events[mark:], node3.ID, agent.Frozen, why) {
		t.Fatal("the FROZEN alarm did not explain that this node's branch cannot reach the split")
	}
	// Deliver a head reaching the split after the freeze. Neither it nor
	// the previously proven peers may be installed under this anchor.
	node3.Log.Source = logclient.Dir(a.dir)
	forkCycle(t, m, staleness+tg, 2)
	wantFrozenTable(t, node3, before, nil)
}

// splitView first corroborates a common prefix, so §11's frozen set
// applies rather than D-071's uncorroborated-first-head drop. The
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
	for _, node := range m.Nodes {
		if peers := held(t, node).Peers; len(peers) != 2 || holdsPeer(peers, afterSplitKey()) {
			t.Fatalf("%s did not start with just its two pre-split peers", node.ID)
		}
	}
	a.enrollAfterSplit(t)
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
		peers := held(t, node).Peers
		if i != 1 {
			if len(peers) != 3 || !holdsPeer(peers, afterSplitKey()) {
				t.Fatalf("%s did not install the device enrolled after the split on A", node.ID)
			}
		} else if len(peers) != 2 || holdsPeer(peers, afterSplitKey()) {
			t.Fatal("branch B installed a device enrolled only on A")
		}
		node.Gossip = true
	}
	return a, b, m
}

// beforeSplitPeers names the expected survivors independently of frozenSet:
// this scenario adds exactly one device after its corroborated prefix.
func beforeSplitPeers(peers []peertable.Peer) []peertable.Peer {
	var kept []peertable.Peer
	for _, peer := range peers {
		if peer.Key != afterSplitKey() {
			kept = append(kept, peer)
		}
	}
	return kept
}

func wantFrozenTable(t *testing.T, node *Node, before heldState, want []peertable.Peer) {
	t.Helper()
	got := held(t, node)
	if !node.Agent.Frozen() {
		t.Fatalf("%s is not frozen", node.ID)
	}
	if len(got.Peers) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got.Peers, want)) {
		t.Fatalf("%s frozen peer table has %d peers, want %d: post-split peer present=%v",
			node.ID, len(got.Peers), len(want), holdsPeer(got.Peers, afterSplitKey()))
	}
	// Enforcement may write a smaller table; authorization state stays held.
	got.Peers, got.Writes = before.Peers, before.Writes
	if !reflect.DeepEqual(before, got) {
		t.Fatalf("%s changed its held checkpoint or published view on the fork", node.ID)
	}
}

func afterSplitKey() peertable.Key { return peertable.Key{42} }

func (f *fixture) enrollAfterSplit(t *testing.T) {
	t.Helper()
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	wg := afterSplitKey()
	req, err := enrollreq.New(f.doc.Net, "after-split", identity.Public().(ed25519.PublicKey), wg[:],
		cosignedAt, map[string]string{"ip": "10.77.0.4/32"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := enrollreq.Sign(req, identity); err != nil {
		t.Fatal(err)
	}
	raw, err := enrollreq.Encode(req)
	if err != nil {
		t.Fatal(err)
	}
	f.append(t, "enroll", map[string]any{"request": raw}, "signer", "signer1", "signer2")
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

func TestT5OnlyTheSkewedNodeAlarmsWithoutChangingEnforcement(t *testing.T) {
	t.Log("Simulated time proves code ordering and bounds; it does not replace the lab's wall-clock measurements.")
	f := newFixture(t)
	// An honest clock must stay quiet even when the cosignature is hours
	// old. This separates wall minus witness time from the actual skew,
	// which subtracts monotonic age (GOSSIP.md §5).
	f.params(t, map[string]any{"staleness": uint64((3 * time.Hour) / time.Second)})
	m := f.mesh(t)
	goodCycle(t, m, 0)
	goodCycle(t, m, 2*time.Hour)
	before := make([]heldState, len(m.Nodes))
	sets := make([]proven.Set, len(m.Nodes))
	for i, node := range m.Nodes {
		before[i], sets[i] = held(t, node), view(t, node)
		if hasEvent(m.Events, node.ID, agent.ClockSkew, "") {
			t.Fatalf("%s reported an old cosignature as clock skew", node.ID)
		}
	}
	start, mark := m.Elapsed, len(m.Events)
	shiftWall(m.Nodes[1], 2*time.Hour)
	var recovered time.Duration
	for cycle := 0; cycle < 3; cycle++ {
		if cycle == 2 {
			recovered = m.Elapsed
			shiftWall(m.Nodes[1], -2*time.Hour)
		}
		round := len(m.Events)
		goodCycle(t, m, tg)
		for _, event := range m.Events[round:] {
			if event.Node != m.Nodes[1].ID || !(cycle < 2 && event.Kind == agent.ClockSkew) {
				t.Fatalf("unexpected event during clock skew and recovery: %+v", event)
			}
		}
		for i, node := range m.Nodes {
			wantAlarm := i == 1 && cycle < 2
			if got := hasEvent(m.Events[round:], node.ID, agent.ClockSkew, "2h0m0s"); got != wantAlarm {
				t.Fatalf("%s CLOCK_SKEW in cycle %d = %v, want %v", node.ID, cycle+1, got, wantAlarm)
			}
			if !wantAlarm && hasEvent(m.Events[round:], node.ID, agent.ClockSkew, "") {
				t.Fatalf("%s alarmed with an honest clock", node.ID)
			}
			if node.Mono != m.Elapsed || node.Agent.Freshness() != freshness.Fresh ||
				hasEvent(m.Events[mark:], node.ID, agent.Degraded, "") || hasEvent(m.Events[mark:], node.ID, agent.HardStale, "") {
				t.Fatalf("%s changed monotonic time or freshness during wall-clock skew", node.ID)
			}
			got, set := held(t, node), view(t, node)
			if set.AgeSeconds == nil || *set.AgeSeconds != int64(m.Elapsed/time.Second) {
				t.Fatalf("%s's age did not follow honest monotonic time", node.ID)
			}
			// Publication time is explicitly local, and age advances with
			// monotonic time. Every authoritative field and peer write must
			// stay unchanged through both the alarm and its recovery.
			set.WrittenAt, set.AgeSeconds = sets[i].WrittenAt, sets[i].AgeSeconds
			got.Published = before[i].Published
			if !reflect.DeepEqual(sets[i], set) || !reflect.DeepEqual(before[i], got) {
				t.Fatalf("%s changed its proven set, held checkpoint or peer table", node.ID)
			}
		}
		if cycle == 0 {
			t.Logf("T5 node2 CLOCK_SKEW latency: %s simulated (one cycle, %s)", m.Elapsed-start, tg)
		}
		if cycle == 2 {
			t.Logf("T5 node2 alarm cessation latency: %s simulated (one cycle, %s)", m.Elapsed-recovered, tg)
		}
	}
}

// shiftWall leaves the monotonic clock and every witness untouched.
func shiftWall(node *Node, delta time.Duration) { node.Wall = node.Wall.Add(delta) }

func TestT7NodesEvictTheRevokedDeviceWithinThePropagationBound(t *testing.T) {
	t.Log("Simulated time proves code ordering and bounds; it does not replace the lab's wall-clock measurements.")
	f := newFixture(t)
	initial, err := logclient.Verify(logclient.Dir(f.dir), f.anchor())
	if err != nil {
		t.Fatal(err)
	}
	// T_c is the replayed params.checkpoint_interval, in seconds (the log
	// command's -checkpoint-interval cadence). T_g is tg, passed by mesh
	// to agent.Config.GossipEvery. T_poll is this scheduler's poll value,
	// used below to call Once, matching nornd's 200 ms DefaultPoll.
	seconds, ok := initial.State.Params["checkpoint_interval"].(uint64)
	if !ok || seconds == 0 {
		t.Fatal("the fixture has no checkpoint interval")
	}
	tc := time.Duration(seconds) * time.Second
	const poll = 200 * time.Millisecond
	bound := tc + tg + poll
	// Keep freshness out of this propagation test. The pending checkpoint
	// may spend the full T_c waiting to become visible to the clients.
	f.params(t, map[string]any{"staleness": uint64((2 * bound) / time.Second)})
	m := f.mesh(t)
	goodCycle(t, m, 0)
	goodCycle(t, m, 0)
	revoked := m.Nodes[2].Device.OwnPublicKey
	before := make([]heldState, 2)
	for i, node := range m.Nodes[:2] {
		before[i] = held(t, node)
		if !holdsPeer(before[i].Peers, revoked) || len(before[i].Peers) != 2 {
			t.Fatalf("%s did not initially install node3 and the other peer", node.ID)
		}
	}
	old := f.snapshot(t)
	for _, node := range m.Nodes {
		node.Log.Source = logclient.Dir(old)
	}
	start, mark := m.Elapsed, len(m.Events)
	f.revoke(t, "pi-cam")
	// Append publishes immediately in tlogstore. Withhold its new directory
	// for a full T_c to model the checkpoint cadence, then let only node1
	// fetch it directly. Node2's direct log stays at the valid old head, so
	// its eviction must come from gossip, with no error-triggered fallback.
	goodCycle(t, m, tc, 1)
	for i, node := range m.Nodes[:2] {
		if !reflect.DeepEqual(before[i].Peers, held(t, node).Peers) {
			t.Fatalf("%s evicted node3 before the new head was delivered", node.ID)
		}
	}
	m.Nodes[0].Log.Source = logclient.Dir(f.dir)
	latencies := map[string]time.Duration{}
	for m.Elapsed-start < bound {
		// Poll node2 first so it cannot see node1's new mirror in the same
		// cycle that node1 first adopts it.
		goodCycle(t, m, poll, 1, 0)
		for i, node := range m.Nodes[:2] {
			now := held(t, node)
			if node.Agent.Freshness() != freshness.Fresh {
				t.Fatalf("%s became stale during revoke propagation", node.ID)
			}
			if holdsPeer(now.Peers, revoked) {
				continue
			}
			if _, seen := latencies[node.ID]; seen {
				continue
			}
			wantPeers := []peertable.Peer{}
			for _, peer := range before[i].Peers {
				if peer.Key != revoked {
					wantPeers = append(wantPeers, peer)
				}
			}
			if !reflect.DeepEqual(wantPeers, now.Peers) || len(now.Devices) != 2 ||
				view(t, node).Checkpoint.Size != f.store.Checkpoint().Size {
				t.Fatalf("%s did not enforce just the revocation from the new head", node.ID)
			}
			for _, device := range now.Devices {
				if device.DeviceID == "pi-cam" {
					t.Fatalf("%s still proves the revoked device", node.ID)
				}
			}
			latencies[node.ID] = m.Elapsed - start
		}
		if len(latencies) == 2 {
			break
		}
	}
	for _, node := range m.Nodes[:2] {
		latency, ok := latencies[node.ID]
		if !ok || latency > bound {
			t.Fatalf("%s did not evict node3 within T_c + T_g + T_poll = %s", node.ID, bound)
		}
		t.Logf("T7 %s eviction latency: %s simulated (bound %s = T_c %s + T_g %s + T_poll %s)", node.ID, latency, bound, tc, tg, poll)
	}
	if !hasEvent(m.Events[mark:], m.Nodes[1].ID, agent.AdoptedFromPeer,
		fmt.Sprintf("took size %d from peer http://10.77.0.1:8099", f.store.Checkpoint().Size)) {
		t.Fatal("node2 did not adopt the revocation from node1 through gossip")
	}
	writeT7Results(t, latencies, bound)
}

func holdsPeer(peers []peertable.Peer, key peertable.Key) bool {
	for _, peer := range peers {
		if peer.Key == key {
			return true
		}
	}
	return false
}

// revoke uses the prefix's two-of-three signer quorum. The store signs and
// cosigns its new checkpoint through the same path as every fixture append.
func (f *fixture) revoke(t *testing.T, id string) {
	t.Helper()
	f.append(t, "revoke", map[string]any{"device_id": id, "reason": "lost"}, "signer", "signer1", "signer2")
}

func writeT7Results(t *testing.T, latencies map[string]time.Duration, bound time.Duration) {
	t.Helper()
	dir := os.Getenv("NORN_SIM_RESULTS")
	if dir == "" {
		return
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return
	}
	// Resolve symlinks as well as relative paths so an explicitly supplied
	// result directory can never put an artifact in the source tree.
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		t.Fatal(err)
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		t.Log("NORN_SIM_RESULTS is inside the source tree; no result file written")
		return
	}
	result := struct {
		Latencies map[string]time.Duration `json:"latencies_ns"`
		Bound     time.Duration            `json:"bound_ns"`
		TimeBasis string                   `json:"time_basis"`
	}{latencies, bound, "Simulated time proves code ordering and bounds; it does not replace the lab's wall-clock measurements."}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "t7.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
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
