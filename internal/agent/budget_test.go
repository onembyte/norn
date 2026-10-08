package agent

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
)

// silentListener accepts every connection and never writes a byte: a proven
// peer behind a tunnel that answers the handshake and nothing else.
func silentListener(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var held []net.Conn
	done := make(chan struct{})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(done)
				return
			}
			held = append(held, c)
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-done
		for _, c := range held {
			c.Close()
		}
	})
	return "http://" + l.Addr().String()
}

// budgetedWatchdog is a watchdog node guarding a table with one rogue key,
// whose three peers are wherever the test says, with a short round budget
// and a per-request bound long enough that r of them would blow it.
func budgetedWatchdog(t *testing.T, peers []string, rec *recorder) (*Agent, *peertable.Fake) {
	t.Helper()
	was := gossip.FetchTimeout()
	gossip.SetTimeout(2 * time.Second)
	t.Cleanup(func() { gossip.SetTimeout(was) })

	fake := peertable.NewFake(provenKeys(t)...)
	fake.Inject(rogue(t))
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(servedLog(t)), Device: fake,
		Mode: reconcile.Watchdog, Emit: rec.emit,
		Now:         func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:        func() time.Duration { return 0 },
		Peers:       func() []string { return peers },
		RoundBudget: 400 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, fake
}

// cycleWithin runs one cycle under a hard deadline, so a regression fails
// rather than hangs, and returns what the cycle returned.
func cycleWithin(t *testing.T, a *Agent, limit time.Duration) error {
	t.Helper()
	finished := make(chan error, 1)
	go func() { finished <- a.Once() }()
	select {
	case err := <-finished:
		return err
	case <-time.After(limit):
		t.Fatalf("Once() is still running after %s; a round of silent peers must cost "+
			"one round budget, not r per-request timeouts", limit)
		return nil
	}
}

// H2-b. After H2-a one silent peer costs one timeout, so r of them cost r
// timeouts, twice: once for checkpoints and once for evidence. That is still
// a cycle that does not reconcile for as long as the slowest neighbours
// decide. A round has one budget; peers it did not reach are peers it did not
// ask, and the table is reconciled all the same.
func TestARoundOfSilentPeersCostsOneBudgetNotRTimeouts(t *testing.T) {
	silent := silentListener(t)
	rec := &recorder{}
	a, fake := budgetedWatchdog(t, []string{silent, silent, silent}, rec)

	// Two rounds (the first head's corroboration, then evidence) at 400 ms
	// each, plus the cycle itself; r × 2 s × 2 would be twelve seconds.
	started := time.Now()
	if err := cycleWithin(t, a, 3*time.Second); err != nil {
		t.Fatalf("the cycle failed: %v", err)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Errorf("the cycle took %s for two 400 ms rounds", took)
	}
	peers, _ := fake.Peers()
	if holds(peers, rogue(t).Key) {
		t.Error("the rogue key survived a watchdog cycle that silent peers delayed")
	}
	if rec.kinds()[PeerRoundCut] == 0 {
		t.Errorf("a round cut short by its budget should say so: %v", rec.kinds())
	}
}

// The evidence round has the same budget on its own. A peer that answers for
// checkpoints and hangs on `/norn/evidence` is the way to show it: the
// checkpoint round corroborates the head at once, and only evidence polling
// can stall.
func TestAnEvidenceRoundHasItsOwnBudget(t *testing.T) {
	handler := gossip.Handler(servedLog(t), "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/evidence") {
			<-r.Context().Done() // never answers
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	rec := &recorder{}
	a, fake := budgetedWatchdog(t, []string{srv.URL, srv.URL, srv.URL}, rec)

	started := time.Now()
	if err := cycleWithin(t, a, 3*time.Second); err != nil {
		t.Fatalf("the cycle failed: %v", err)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Errorf("the cycle took %s with only the evidence round stalling", took)
	}
	if rec.kinds()[FirstHeadUncorroborated] != 0 {
		t.Error("the peers answered for checkpoints; the head was corroborated")
	}
	if peers, _ := fake.Peers(); holds(peers, rogue(t).Key) {
		t.Error("the rogue key survived a watchdog cycle that evidence polling delayed")
	}
}
