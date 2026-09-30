package gossip

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// SEC-003. `Peer.Fetch` was the one HTTP client in the tree with no deadline,
// and it runs before reconcile: a proven peer that accepted the handshake and
// never answered held `Once()` forever, on every node that drew it. These
// tests are the two ways a peer stays silent, each bounded.

// shortTimeout shrinks the bound for the duration of a test. The tests in
// this package do not run in parallel.
func shortTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	was := FetchTimeout()
	SetTimeout(d)
	t.Cleanup(func() { SetTimeout(was) })
}

// silentPeer accepts every connection and never writes a byte.
func silentPeer(t *testing.T) string {
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

func TestASilentPeerCostsABoundedWaitNotTheCycle(t *testing.T) {
	shortTimeout(t, 300*time.Millisecond)
	peer := Peer(silentPeer(t))

	started := time.Now()
	_, err := peer.Fetch("checkpoint")
	took := time.Since(started)
	if err == nil {
		t.Fatal("a peer that never answers produced a checkpoint")
	}
	if took > 5*time.Second {
		t.Fatalf("a silent peer held the reader for %s; the bound is %s", took, FetchTimeout())
	}
}

// The other silence: a status line, then a body that never finishes. The
// overall deadline covers it; the header deadline alone would not.
func TestATricklingPeerCostsABoundedWait(t *testing.T) {
	shortTimeout(t, 300*time.Millisecond)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 100; i++ {
			if _, err := w.Write([]byte("n")); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}))
	t.Cleanup(srv.Close)

	started := time.Now()
	_, err := Peer(srv.URL).Fetch("checkpoint")
	took := time.Since(started)
	if err == nil {
		t.Fatal("a body that never ends was accepted")
	}
	if took > 5*time.Second {
		t.Fatalf("a trickling peer held the reader for %s; the bound is %s", took, FetchTimeout())
	}
}

// A peer serves bytes at the documented paths or it does not. Following it
// elsewhere would let one compromised neighbour choose where this node reads.
func TestAPeerIsNeverFollowedToAnotherAddress(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("a checkpoint from somewhere else"))
	}))
	t.Cleanup(elsewhere.Close)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirecting.Close)

	_, err := Peer(redirecting.URL).Fetch("checkpoint")
	if err == nil {
		t.Fatal("a redirect was followed")
	}
	var urlErr interface{ Unwrap() error }
	if !errors.As(err, &urlErr) || !strings.Contains(err.Error(), "does not redirect") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}
