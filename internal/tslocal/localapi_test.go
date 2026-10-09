package tslocal

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/peertable"
)

func nodeKey(b byte) string { return "nodekey:" + strings.Repeat(hex.EncodeToString([]byte{b}), 32) }

// The transport runs a real Handler without a listening socket. The pipe
// keeps notifications streaming rather than buffering them until EOF.
type handlerTransport struct{ handler http.Handler }

func (h handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path != "/localapi/v0/watch-ipn-bus" {
		w := httptest.NewRecorder()
		h.handler.ServeHTTP(w, r)
		return w.Result(), nil
	}
	reader, writer := io.Pipe()
	w := &streamWriter{header: make(http.Header), writer: writer, ready: make(chan struct{})}
	go func() { h.handler.ServeHTTP(w, r); writer.Close() }()
	select {
	case <-w.ready:
		return &http.Response{StatusCode: w.status, Header: w.header, Body: reader}, nil
	case <-r.Context().Done():
		reader.Close()
		return nil, r.Context().Err()
	}
}

type streamWriter struct {
	header http.Header
	writer *io.PipeWriter
	ready  chan struct{}
	once   sync.Once
	status int
}

func (w *streamWriter) Header() http.Header { return w.header }
func (w *streamWriter) WriteHeader(status int) {
	w.once.Do(func() { w.status = status; close(w.ready) })
}
func (w *streamWriter) Write(b []byte) (int, error) { w.WriteHeader(200); return w.writer.Write(b) }
func (w *streamWriter) Flush()                      { w.WriteHeader(200) }

type fakeAPI struct {
	mu       sync.Mutex
	peers    map[string]any
	bus      chan string
	watching chan struct{}
	paths    []string
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{peers: map[string]any{nodeKey(1): map[string]any{"PublicKey": nodeKey(1)}}, bus: make(chan string, 8), watching: make(chan struct{})}
}
func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	switch r.URL.Path {
	case "/localapi/v0/status":
		f.mu.Lock()
		defer f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"Self": map[string]any{"PublicKey": nodeKey(9)}, "Peer": f.peers})
	case "/localapi/v0/watch-ipn-bus":
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(f.watching)
		for {
			select {
			case <-r.Context().Done():
				return
			case message := <-f.bus:
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
func (f *fakeAPI) set(keys ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers = map[string]any{}
	for _, key := range keys {
		f.peers[key] = map[string]any{"PublicKey": key}
	}
}

func TestNodeKeysAreDecodedAndMalformedKeysAreRefused(t *testing.T) {
	want := peertable.Key{1}
	got, err := ParseNodeKey("nodekey:01" + strings.Repeat("00", 31))
	if err != nil || got != want {
		t.Fatalf("decoded key = %v, error = %v", got, err)
	}
	for _, bad := range []string{"", nodeKey(1)[8:], "nodekey:00", "nodekey:" + strings.Repeat("gg", 32), " nodekey:" + strings.Repeat("00", 32), "nodekey:" + strings.Repeat("00", 33)} {
		if _, err := ParseNodeKey(bad); err == nil {
			t.Errorf("accepted malformed key %q", bad)
		}
	}
}
func TestStatusProducesPeersAndRemovalLeavesTheTable(t *testing.T) {
	api := newFakeAPI()
	d := New("", handlerTransport{api})
	peers, err := d.Peers()
	if err != nil || len(peers) != 1 {
		t.Fatalf("status peers = %v, error = %v", peers, err)
	}
	want, _ := ParseNodeKey(nodeKey(1))
	if peers[0].Key != want {
		t.Fatal("status used the wrong public key")
	}
	own, err := d.OwnKey()
	wantOwn, _ := ParseNodeKey(nodeKey(9))
	if err != nil || own != wantOwn {
		t.Fatalf("own key = %v, error = %v", own, err)
	}
	api.set()
	peers, err = d.Peers()
	if err != nil || len(peers) != 0 {
		t.Fatalf("removed peer remains: %v, error = %v", peers, err)
	}
}
func TestEveryWriteIsRefusedWithoutCallingTheLocalAPI(t *testing.T) {
	api := newFakeAPI()
	d := New("", handlerTransport{api})
	for _, write := range []func() error{func() error { return d.Replace(nil) }, func() error { return d.Remove(nil) }, func() error { return d.UpdateEndpoints(nil) }} {
		if err := write(); !errors.Is(err, ErrReadOnly) {
			t.Errorf("write error = %v, want observe-only refusal", err)
		}
	}
	if len(api.paths) != 0 {
		t.Fatal("a write contacted tailscaled")
	}
}
func TestBusNotificationsWakeTheReaderAndRemovalIsVisible(t *testing.T) {
	api := newFakeAPI()
	d := New("", handlerTransport{api})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := d.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	api.set()
	api.bus <- `{"Version":"fake"}`
	select {
	case err := <-events:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("bus notification did not wake the reader")
	}
	peers, err := d.Peers()
	if err != nil || len(peers) != 0 {
		t.Fatalf("removed peer remains: %v, error = %v", peers, err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if !strings.Contains(strings.Join(api.paths, "\n"), "GET /localapi/v0/watch-ipn-bus?mask=512") {
		t.Fatalf("watch options = %v", api.paths)
	}
}
func TestAMissingSocketIsNamedWithoutAPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sock")
	d := New(path, nil)
	if _, err := d.Peers(); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("missing socket error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := d.Watch(ctx); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("watch socket error = %v", err)
	}
}
func TestMalformedStatusKeysAreRefused(t *testing.T) {
	api := newFakeAPI()
	d := New("", handlerTransport{api})
	for _, peers := range []map[string]any{{"bad": map[string]any{"PublicKey": "bad"}}, {nodeKey(1): map[string]any{"PublicKey": nodeKey(2)}}, {nodeKey(1): map[string]any{}}} {
		api.mu.Lock()
		api.peers = peers
		api.mu.Unlock()
		if _, err := d.Peers(); err == nil {
			t.Errorf("accepted malformed or inconsistent status %v", peers)
		}
	}
}
