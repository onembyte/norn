package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/agent"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
	"github.com/onembyte/norn/internal/tslocal"
)

func TestTailscaleRefusesOwnerAndWatchdogBeforeOpeningAnything(t *testing.T) {
	previous := openTailscale
	opened := 0
	openTailscale = func(string) (peertable.Device, error) { opened++; return peertable.NewFake(), nil }
	t.Cleanup(func() { openTailscale = previous })
	for _, mode := range []string{"owner", "watchdog"} {
		config := Config{Backend: "tailscale", Mode: mode, Trust: filepath.Join(vectors(), "trust.cbor"), Log: filepath.Join(vectors(), "served"), RunDir: t.TempDir(), StateDir: t.TempDir()}
		config.SetGossipPort(0, true)
		cycle, _, err := build(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err == nil || cycle != nil || !strings.Contains(err.Error(), "D-014") {
			t.Errorf("started a tailscale %s agent: cycle=%v, error=%v", mode, cycle, err)
		}
	}
	if opened != 0 {
		t.Errorf("opened tailscaled %d times before refusing enforcement", opened)
	}
	bin := nornd(t)
	for _, mode := range []string{"owner", "watchdog"} {
		out, err := runNornd(t, bin, "-backend", "tailscale", "-mode", mode, "-once")
		if err == nil || !strings.Contains(out, "D-014") || !strings.Contains(out, "no UAPI") || !strings.Contains(out, "patching tailscaled") {
			t.Errorf("%s did not get the D-014 refusal: %v\n%s", mode, err, out)
		}
	}
}
func TestTailscaleUsesTheConfiguredSocketAndObserveDefault(t *testing.T) {
	bin := nornd(t)
	socket := filepath.Join(t.TempDir(), "missing.sock")
	config := filepath.Join(t.TempDir(), "nornd.toml")
	body := "backend = \"tailscale\"\ntailscale_socket = \"" + socket + "\"\ntrust = \"" + filepath.Join(vectors(), "trust.cbor") + "\"\n"
	if err := os.WriteFile(config, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runNornd(t, bin, "-config", config, "-once")
	if err == nil || !strings.Contains(out, socket) || !strings.Contains(out, "mode=observe") {
		t.Fatalf("configured socket/default mode: %v\n%s", err, out)
	}
	override := filepath.Join(t.TempDir(), "override.sock")
	out, err = runNornd(t, bin, "-config", config, "-tailscale-socket", override, "-once")
	if err == nil || !strings.Contains(out, override) || strings.Contains(out, socket) {
		t.Fatalf("socket flag did not override config: %v\n%s", err, out)
	}
	out, err = runNornd(t, bin, "-backend", "tailscale", "-trust", filepath.Join(vectors(), "trust.cbor"), "-once")
	if err == nil || !strings.Contains(out, tslocal.DefaultSocket) {
		t.Fatalf("default socket: %v\n%s", err, out)
	}
}
func TestUnknownBackendsAreRefused(t *testing.T) {
	out, err := runNornd(t, nornd(t), "-backend", "typo", "-once")
	if err == nil || !strings.Contains(out, "unknown backend") {
		t.Fatalf("unknown backend: %v\n%s", err, out)
	}
}

// A channel transport and Handler exercise the streaming HTTP client without
// a socket. Status is changed before a notification, just as U6 must confirm
// tailscaled does; no notification payload is treated as a peer table.
type localAPITransport struct{ handler http.Handler }

func (h localAPITransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path != "/localapi/v0/watch-ipn-bus" {
		w := httptest.NewRecorder()
		h.handler.ServeHTTP(w, r)
		return w.Result(), nil
	}
	reader, writer := io.Pipe()
	w := &localAPIWriter{header: make(http.Header), writer: writer, ready: make(chan struct{})}
	go func() { h.handler.ServeHTTP(w, r); writer.Close() }()
	select {
	case <-w.ready:
		return &http.Response{StatusCode: w.status, Status: strconv.Itoa(w.status) + " " + http.StatusText(w.status), Header: w.header, Body: reader}, nil
	case <-r.Context().Done():
		reader.Close()
		return nil, r.Context().Err()
	}
}

type localAPIWriter struct {
	header http.Header
	writer *io.PipeWriter
	ready  chan struct{}
	once   sync.Once
	status int
}

func (w *localAPIWriter) Header() http.Header         { return w.header }
func (w *localAPIWriter) WriteHeader(code int)        { w.once.Do(func() { w.status = code; close(w.ready) }) }
func (w *localAPIWriter) Write(b []byte) (int, error) { w.WriteHeader(200); return w.writer.Write(b) }
func (w *localAPIWriter) Flush()                      { w.WriteHeader(200) }

type localAPIHandler struct {
	mu            sync.Mutex
	keys          []peertable.Key
	self          peertable.Key
	bus           chan string
	reads         int
	watchRequests chan struct{}
	failWatches   int
	holdWatch     <-chan struct{}
}

func (h *localAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/localapi/v0/status":
		h.mu.Lock()
		defer h.mu.Unlock()
		h.reads++
		peers := map[string]any{}
		for _, key := range h.keys {
			text := "nodekey:" + hex.EncodeToString(key[:])
			peers[text] = map[string]string{"PublicKey": text}
		}
		json.NewEncoder(w).Encode(map[string]any{"Self": map[string]string{"PublicKey": "nodekey:" + hex.EncodeToString(h.self[:])}, "Peer": peers})
	case "/localapi/v0/watch-ipn-bus":
		h.mu.Lock()
		bus, requests, hold := h.bus, h.watchRequests, h.holdWatch
		fail := h.failWatches > 0
		if fail {
			h.failWatches--
		}
		h.mu.Unlock()
		if requests != nil {
			requests <- struct{}{}
		}
		if hold != nil {
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case message, ok := <-bus:
				if !ok {
					return
				}
				if _, err := io.WriteString(w, message+"\n"); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}
	default:
		http.NotFound(w, r)
	}
}
func (h *localAPIHandler) set(keys []peertable.Key) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keys = append([]peertable.Key(nil), keys...)
}

func tailscaleCycle(t *testing.T) (*agent.Agent, *localAPIHandler, <-chan agent.Event) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	fetcher := logclient.Dir(filepath.Join(vectors(), "served"))
	result, err := logclient.Verify(fetcher, logclient.Anchor{Anchor: replay.FromTrust(anchor), LogKeys: []string{anchor.LogKey}, Policy: anchor.Policy})
	if err != nil {
		t.Fatal(err)
	}
	var keys []peertable.Key
	for _, id := range proven.Devices(result.State, proven.EvaluationTime(result)) {
		raw, err := hex.DecodeString(result.State.Devices[id].WgPk)
		if err != nil {
			t.Fatal(err)
		}
		key, err := peertable.KeyFromBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		t.Fatal("fixture has no proven peers")
	}
	api := &localAPIHandler{keys: keys, self: peertable.Key{99}, bus: make(chan string, 8)}
	events := make(chan agent.Event, 100)
	cycle, err := agent.New(agent.Config{Anchor: anchor, Fetcher: fetcher, Device: tslocal.New("", localAPITransport{api}), Mode: reconcile.Observe, Emit: func(e agent.Event) { events <- e }})
	if err != nil {
		t.Fatal(err)
	}
	return cycle, api, events
}
func TestAPollSeesAProvenPeerSilentlyAndAnUnprovenPeer(t *testing.T) {
	cycle, api, events := tailscaleCycle(t)
	if err := cycle.Once(); err != nil {
		t.Fatal(err)
	}
	for len(events) > 0 {
		if event := <-events; event.Kind == reconcile.UnprovenPeer {
			t.Fatal("a proven peer alarmed")
		}
	}
	api.mu.Lock()
	api.keys = append(api.keys, peertable.Key{44})
	api.mu.Unlock()
	if err := cycle.Once(); err != nil {
		t.Fatal(err)
	}
	found := false
	for len(events) > 0 {
		event := <-events
		if event.Kind == reconcile.UnprovenPeer && event.Peer.Key == (peertable.Key{44}) {
			found = true
		}
	}
	if !found {
		t.Fatal("poll did not alarm on an unproven peer")
	}
}
func TestABusEventRaisesUnprovenPeerBeforeTheNextPoll(t *testing.T) {
	cycle, api, events := tailscaleCycle(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- loop(ctx, cycle, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	// Wait for both initial status snapshots before adding the rogue, so
	// the initial cycle cannot accidentally be the source of the alarm.
	deadline := time.After(2 * time.Second)
	for {
		api.mu.Lock()
		reads := api.reads
		api.mu.Unlock()
		if reads >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("initial cycle did not read status")
		case <-time.After(time.Millisecond):
		}
	}
	// Peers() already received the initial snapshot before the rogue is added.
	api.mu.Lock()
	original := append([]peertable.Key(nil), api.keys...)
	api.mu.Unlock()
	rogue := peertable.Key{44}
	api.set(append(append([]peertable.Key(nil), original...), rogue))
	api.bus <- `{}`
	timeout := time.After(2 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Kind != reconcile.UnprovenPeer {
				continue
			}
			if event.Peer.Key != rogue {
				t.Fatalf("a proven peer alarmed: %v", event.Peer.Key)
			}
			api.set(original)
			api.bus <- `{}`
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			return
		case err := <-done:
			t.Fatalf("loop exited before event: %v", err)
		case <-timeout:
			t.Fatal("bus event did not raise UNPROVEN_PEER before the one-hour poll")
		}
	}
}

// Backend selection must reach the agent, not just the startup log.
func TestTailscaleBuildsAnObserveAgentWithTheSelectedSocket(t *testing.T) {
	previous := openTailscale
	var selected string
	openTailscale = func(socket string) (peertable.Device, error) { selected = socket; return peertable.NewFake(), nil }
	t.Cleanup(func() { openTailscale = previous })
	config := Config{Backend: "tailscale", TailscaleSocket: "/operator/tailscaled.sock", Trust: filepath.Join(vectors(), "trust.cbor"), Log: filepath.Join(vectors(), "served"), RunDir: t.TempDir(), StateDir: t.TempDir()}
	config.SetGossipPort(0, true)
	cycle, _, err := build(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if cycle.Mode() != reconcile.Observe || selected != config.TailscaleSocket {
		t.Fatalf("mode=%v, selected socket=%q", cycle.Mode(), selected)
	}
	if err := cycle.Once(); err != nil {
		t.Fatal(err)
	}
}
