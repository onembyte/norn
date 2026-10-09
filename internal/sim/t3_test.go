package sim

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/agent"
	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/monitor"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/receipt"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/witness"
)

func TestT3HonestWitnessesKeepTheLyingLogOnItsHeldBranch(t *testing.T) {
	t.Log("Simulated time proves code ordering and bounds; it does not replace the lab's wall-clock measurements.")
	t.Run("node2 refuses B and carries A from peers", func(t *testing.T) {
		a, b, m, _ := lyingLog(t)
		acp, bcp := a.store.Checkpoint(), b.store.Checkpoint()
		if bcp.Size < acp.Size || bcp.Root == acp.Root {
			t.Fatal("the lying log did not produce a conflicting head B at least as large as A")
		}
		node := m.Nodes[1]
		before, set := held(t, node), view(t, node)
		start, mark := m.Elapsed, len(m.Events)
		// Isolate direct refusal first. Peer recovery must not hide a quorum
		// bypass or turn an uncorroborated head into a fork accusation.
		node.Gossip = false
		errs := m.Cycle(time.Second, 1)
		if code, _ := refusal.CodeOf(errs[0]); code != refusal.Quorum {
			t.Errorf("node2 refusal = %v, want quorum", errs[0])
		}
		if !reflect.DeepEqual(before, held(t, node)) || !reflect.DeepEqual(set, view(t, node)) {
			t.Error("node2 changed its held checkpoint or proven set on B")
		}
		if !hasEvent(m.Events[mark:], node.ID, agent.VerifyFailed, "witness policy") {
			t.Error("node2 did not report the direct quorum refusal")
		}
		if node.Agent.Frozen() || hasEvent(m.Events[mark:], node.ID, agent.Fork, "") {
			t.Error("node2 accused or froze on B without a quorum")
		}
		t.Logf("T3 node2 under-quorum B refusal latency: %s simulated", m.Elapsed-start)
		node.Gossip = true
		goodCycle(t, m, tg, 1)
		if held(t, node).Checkpoint != before.Checkpoint || !reflect.DeepEqual(view(t, node).Devices, set.Devices) {
			t.Error("node2 did not stay on A from its peers")
		}

		// Only the other nodes can fetch A's successor directly. B remains
		// node2's source, so its new held head must come through real gossip.
		a.at = m.Nodes[0].Wall
		a.revoke(t, "pi-cam")
		goodCycle(t, m, 0, 0, 2)
		successor, err := logclient.Verify(logclient.Dir(a.dir), a.anchor())
		if err != nil {
			t.Fatal(err)
		}
		root, err := successor.Tree.HeadAt(acp.Size)
		if err != nil || root != acp.Root {
			t.Fatal("the successor does not extend A")
		}
		start = m.Elapsed
		for m.Elapsed-start < 2*tg && view(t, node).Checkpoint.Size != successor.Checkpoint.Size {
			goodCycle(t, m, tg, 1)
		}
		raw, err := os.ReadFile(filepath.Join(a.dir, "checkpoint"))
		if err != nil {
			t.Fatal(err)
		}
		if held(t, node).Checkpoint != string(raw) || len(view(t, node).Devices) != 2 ||
			!reflect.DeepEqual(view(t, node).Devices, view(t, m.Nodes[0]).Devices) ||
			!hasEvent(m.Events[mark:], node.ID, agent.AdoptedFromPeer, fmt.Sprintf("took size %d", successor.Checkpoint.Size)) {
			t.Error("node2 did not adopt and enforce A's successor from its peers within 2*T_g")
		}
		for _, n := range m.Nodes {
			if n.Agent.Frozen() || hasEvent(m.Events[mark:], n.ID, agent.Fork, "") || hasEvent(m.Events[mark:], n.ID, agent.Frozen, "") {
				t.Errorf("%s accused or froze on a head without a quorum", n.ID)
			}
		}
		t.Logf("T3 node2 A-successor peer adoption latency: %s simulated (bound %s)", m.Elapsed-start, 2*tg)
	})
	t.Run("the receipt exposes the log after witness time passes its deadline", func(t *testing.T) {
		a, b, m, signed := lyingLog(t)
		raw, err := b.store.Entry(b.store.Checkpoint().Size - 1)
		if err != nil {
			t.Fatal(err)
		}
		leaf := entry.LeafHash(raw)
		promise, err := receipt.Check(signed, []string{a.doc.LogKey}, a.doc.Origin, leaf, m.Nodes[0].Wall)
		if err != nil {
			t.Fatal(err)
		}
		inbox := monitor.NewInbox()
		if err := inbox.Add(signed, a.doc); err != nil {
			t.Fatal(err)
		}
		start := m.Elapsed
		check := func(wantAlert bool) {
			t.Helper()
			result, err := logclient.Verify(logclient.Dir(a.dir), a.anchor())
			if err != nil {
				t.Fatal(err)
			}
			alerts := inbox.Check(result, monitor.Default())
			if wantAlert {
				if len(alerts) != 1 || alerts[0].Rule != "receipt-deadline" || alerts[0].Level != monitor.Critical ||
					alerts[0].Subject != fmt.Sprintf("%x", leaf[:8]) || !strings.Contains(alerts[0].Message, "proof it broke its word") {
					t.Fatalf("missing receipt-deadline proof after witness deadline: %+v", alerts)
				}
			} else if len(alerts) != 0 {
				t.Fatalf("receipt alarm before witness time passed deadline: %+v", alerts)
			}
			if inbox.Pending() != 1 {
				t.Fatal("the omitted leaf's receipt was forgotten")
			}
		}
		check(false)
		// Wall time alone cannot prove omission. Hold witness time at A,
		// then exactly at the deadline, and finally one second beyond it.
		goodCycle(t, m, 2*tg+time.Second, 0, 2)
		check(false)
		a.at = promise.DeadlineTime()
		if err := a.store.Republish(); err != nil {
			t.Fatal(err)
		}
		check(false)
		a.at = m.Nodes[0].Wall
		if err := a.store.Republish(); err != nil {
			t.Fatal(err)
		}
		check(true)
		t.Logf("T3 monitor receipt-deadline (GOSSIP LOG_MISBEHAVIOUR) latency: %s simulated from receipt; %s after deadline", m.Elapsed-start, a.at.Sub(promise.DeadlineTime()))
	})
}

func lyingLog(t *testing.T) (*fixture, *fixture, *Mesh, string) {
	t.Helper()
	a, b := newFixture(t), newFixture(t)
	a.params(t, map[string]any{"staleness": uint64(60)})
	m := a.mesh(t)
	goodCycle(t, m, 0)
	goodCycle(t, m, 0)
	// There is no witness server in this tree. Model honest cosigners as
	// holding A and refusing a different root at that size. Their responses
	// run through witness.Client and Submitter, including ConflictError's
	// retry, in memory. The fixture's existing cosigners genuinely signed A.
	b.witnesses = 0
	b.revoke(t, "pi-cam")
	var clients []*witness.Client
	var holders []*heldWitness
	for _, name := range []string{"pi", "vps", "friend"} {
		w := &heldWitness{held: a.store.Checkpoint(), logKey: a.doc.LogKey,
			name: "norn-witness/" + name, key: key(t, "witness-"+name)}
		holders = append(holders, w)
		clients = append(clients, &witness.Client{Name: w.name, URL: "http://witness.invalid",
			Key: note.CosignerVerifierKey(w.name, w.key.Public().(ed25519.PublicKey)), HTTP: &http.Client{Transport: w}})
	}
	var mu sync.Mutex
	var reported []error
	submitter := witness.NewSubmitter(clients, witnessProofs{b}, func(err error) {
		mu.Lock()
		defer mu.Unlock()
		reported = append(reported, err)
	})
	logSigned, err := b.store.Checkpoint().Sign(key(t, "logkey"))
	if err != nil {
		t.Fatal(err)
	}
	refused, err := submitter.Cosign(logSigned)
	if err != nil || refused != logSigned || len(reported) != len(clients) {
		t.Fatalf("the witnesses did not leave B signed only by the log: %v (%d refusals)", err, len(reported))
	}
	for _, w := range holders {
		if w.conflicts != 1 || w.refusals != 1 {
			t.Fatalf("%s did not correct the starting size then refuse B: %d conflicts, %d refusals", w.name, w.conflicts, w.refusals)
		}
	}
	for _, err := range reported {
		if !errors.Is(err, witness.ErrWitness) || !strings.Contains(err.Error(), "could not verify consistency") {
			t.Fatalf("the client's witness refusal was lost: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(b.dir, "checkpoint"), []byte(refused), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := tlog.Verify(refused, []string{a.doc.LogKey}); err != nil {
		t.Fatalf("B is not genuinely log-signed: %v", err)
	}
	rules, err := policy.Parse(a.doc.Policy)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := cosign.Verify(refused, rules.Keys())
	if err != nil || len(sigs) != 0 || rules.Satisfied(nil) {
		t.Fatalf("B's missing cosignatures are not genuinely missing: %v (%d witnesses)", err, len(sigs))
	}
	raw, err := b.store.Entry(b.store.Checkpoint().Size - 1)
	if err != nil {
		t.Fatal(err)
	}
	text, err := note.ReceiptText(a.doc.Origin, entry.LeafHash(raw), uint64(cosignedAt)+uint64(2*tg/time.Second))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := note.Sign(text, a.doc.Origin, key(t, "logkey"))
	if err != nil {
		t.Fatal(err)
	}
	m.Nodes[1].Log.Source = logclient.Dir(b.dir)
	return a, b, m, signed
}

// Equal-size heads need no proof hashes; the honest witness compares roots.
// The submitter still asks the real store for each proof rather than using
// fabricated hashes, including its retry from the size the witness names.
type witnessProofs struct{ f *fixture }

func (p witnessProofs) ConsistencyProof(old int64) ([][]byte, error) {
	if old == 0 {
		return nil, nil
	}
	proof, err := p.f.store.ConsistencyProof(old)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, hash := range proof {
		out = append(out, bytes.Clone(hash[:]))
	}
	return out, nil
}

type heldWitness struct {
	held                tlog.Checkpoint
	logKey, name        string
	key                 ed25519.PrivateKey
	conflicts, refusals int
}

func (w *heldWitness) RoundTrip(req *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	request, signed, ok := strings.Cut(string(raw), "\n\n")
	if !ok || req.Method != http.MethodPost || req.URL.Path != "/add-checkpoint" {
		return nil, fmt.Errorf("sim: malformed witness request")
	}
	cp, err := tlog.Verify(signed, []string{w.logKey})
	if err != nil {
		return nil, err
	}
	response := httptest.NewRecorder()
	if request != fmt.Sprintf("old %d", w.held.Size) {
		w.conflicts++
		response.Header().Set("Content-Type", "text/x.tlog.size")
		response.WriteHeader(http.StatusConflict)
		_, _ = fmt.Fprintf(response, "%d\n", w.held.Size)
	} else if cp != w.held {
		w.refusals++
		response.WriteHeader(http.StatusUnprocessableEntity)
	} else {
		text, _, err := note.Split(signed)
		if err != nil {
			return nil, err
		}
		line, err := cosign.Sign(text, w.name, w.key, time.Unix(cosignedAt, 0))
		if err != nil {
			return nil, err
		}
		_, _ = fmt.Fprintln(response, line)
	}
	return response.Result(), nil
}
