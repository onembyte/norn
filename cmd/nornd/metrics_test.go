package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/agent"
	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/trust"
)

func metricsCycle(t *testing.T) *agent.Agent {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	cycle, err := agent.New(agent.Config{Anchor: doc, Fetcher: logclient.Dir(filepath.Join(vectors(), "served")), Device: peertable.NewFake()})
	if err != nil {
		t.Fatal(err)
	}
	return cycle
}
func TestMetricsIsReadOnlyLikeGossip(t *testing.T) {
	handler := gossipHandler(t.TempDir(), "", metricsCycle(t))
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, "/metrics", nil))
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("%s: status=%d Allow=%q", method, w.Code, w.Header().Get("Allow"))
		}
	}
	for _, method := range []string{"GET", "HEAD"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, "/metrics", nil))
		if w.Code != 200 || w.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
			t.Fatalf("%s: %d %v", method, w.Code, w.Header())
		}
		if method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("HEAD has a body")
		}
		if method == "GET" && !strings.Contains(w.Body.String(), "# TYPE norn_checkpoint_size gauge") {
			t.Fatal("GET has no exposition")
		}
	}
}
func TestMetricsExistsOnlyOnTheGossipListenerAndGossipOffServesNone(t *testing.T) {
	oldDevice, oldTunnel, oldListen, oldServe := openDevice, tunnelAddress, listenGossip, serveGossipHTTP
	t.Cleanup(func() {
		openDevice = oldDevice
		tunnelAddress = oldTunnel
		listenGossip = oldListen
		serveGossipHTTP = oldServe
	})
	openDevice = func(string) (peertable.Device, error) { return peertable.NewFake(), nil }
	calls := 0
	var bound string
	var handler http.Handler
	tunnelAddress = func(iface string, port int) (string, error) {
		if iface != "wg-test" || port != 8100 {
			t.Fatalf("address derivation: %s %d", iface, port)
		}
		return "10.9.0.1:8100", nil
	}
	listeners := make(chan http.Handler, 1)
	listenGossip = func(network, addr string) (net.Listener, error) {
		if network != "tcp" {
			t.Fatalf("listener network = %s", network)
		}
		calls++
		bound = addr
		return metricsListener{}, nil
	}
	serveGossipHTTP = func(server *http.Server, _ net.Listener) error {
		listeners <- server.Handler
		return http.ErrServerClosed
	}
	config := Config{Interface: "wg-test", Trust: filepath.Join(vectors(), "trust.cbor"), Log: filepath.Join(vectors(), "served"), RunDir: t.TempDir(), StateDir: t.TempDir()}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, _, err := build(config, logger); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || bound != "10.9.0.1:8100" {
		t.Fatalf("listener calls=%d address=%s", calls, bound)
	}
	select {
	case handler = <-listeners:
	case <-time.After(time.Second):
		t.Fatal("gossip server did not start")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 {
		t.Fatalf("gossip listener metrics status=%d", w.Code)
	}
	for _, other := range []http.Handler{gossip.Handler(t.TempDir(), ""), http.DefaultServeMux} {
		w := httptest.NewRecorder()
		other.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		if w.Code != 404 {
			t.Fatalf("metrics exposed elsewhere: %d", w.Code)
		}
	}
	config.SetGossipPort(0, true)
	calls = 0
	if _, _, err := build(config, logger); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("gossip off still started metrics listener")
	}
}

// The server's handler is exercised directly; no socket or HTTP client is
// needed to check which listener actually receives it.
type metricsListener struct{}

func (metricsListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (metricsListener) Close() error              { return nil }
func (metricsListener) Addr() net.Addr            { return &net.TCPAddr{} }
