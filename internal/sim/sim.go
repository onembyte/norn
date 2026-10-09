// Package sim runs real agents on a serial, simulated timeline. The only
// network is an in-memory dispatch to each node's real gossip handler.
package sim

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/onembyte/norn/internal/agent"
	"github.com/onembyte/norn/internal/endpoint"
	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/trust"
)

// Fetcher can follow a live log, serve a frozen directory or another branch,
// or fail every request. Changing Source never changes how an agent verifies it.
type Fetcher struct {
	Source  logclient.Fetcher
	Stalled bool
}

func (f *Fetcher) Fetch(path string) ([]byte, error) {
	if f.Stalled {
		return nil, fmt.Errorf("sim: log stalled")
	}
	return f.Source.Fetch(path)
}

// Identity associates a proven device with its tunnel address. The log must
// grant this route, or explicitly select advisory routes (§13.1).
type Identity struct {
	ID     string
	Key    peertable.Key
	Prefix netip.Prefix
}

// Event records when and where an agent spoke, in deterministic emission order.
type Event struct {
	At   time.Duration
	Node string
	agent.Event
}

// Node owns its clocks, log source, interface and persistent files. Gossip
// can be disabled to isolate a direct log refusal from successful peer recovery.
type Node struct {
	ID     string
	Agent  *agent.Agent
	Device *peertable.Fake
	Log    *Fetcher
	Wall   time.Time
	Mono   time.Duration
	Dir    string
	Gossip bool
}

// Mesh owns a fixed node order. It must be driven serially: Cycle installs
// its transport only while its agents run, then restores the previous one.
type Mesh struct {
	Nodes    []*Node
	Events   []Event
	Elapsed  time.Duration
	handlers map[string]http.Handler
}

const Port = 8099

func New(dir string, anchor *trust.Trust, source logclient.Fetcher, identities []Identity, wall time.Time, gossipEvery time.Duration) (*Mesh, error) {
	m := &Mesh{handlers: make(map[string]http.Handler)}
	hints := endpoint.Static{Peers: make(map[string]endpoint.Hints)}
	for _, id := range identities {
		hints.Peers[id.ID] = endpoint.Hints{AllowedIPs: []netip.Prefix{id.Prefix}}
	}
	for i, id := range identities {
		n := &Node{ID: id.ID, Device: peertable.NewFake(), Log: &Fetcher{Source: source}, Wall: wall,
			Dir: filepath.Join(dir, fmt.Sprintf("node%d", i+1)), Gossip: true}
		n.Device.OwnPublicKey, n.Device.MaskPrefixes = id.Key, true
		a, err := agent.New(agent.Config{
			Anchor: anchor, Fetcher: n.Log, Device: n.Device, Provider: hints,
			Mode: reconcile.Owner, RunDir: n.Dir,
			Now: func() time.Time { return n.Wall }, Mono: func() time.Duration { return n.Mono },
			Peers: func() []string {
				if !n.Gossip {
					return nil
				}
				return n.Agent.PeerAddresses(Port)
			},
			PeerOrder: rand.New(rand.NewSource(int64(i + 1))),
			Fanout:    len(identities), GossipEvery: gossipEvery,
			Emit: func(e agent.Event) { m.Events = append(m.Events, Event{At: m.Elapsed, Node: n.ID, Event: e}) },
		})
		if err != nil {
			return nil, err
		}
		n.Agent = a
		addr, ok := gossip.Address([]netip.Prefix{id.Prefix}, Port)
		if !ok {
			return nil, fmt.Errorf("sim: %s has no gossip address", id.ID)
		}
		if _, exists := m.handlers[addr]; exists {
			return nil, fmt.Errorf("sim: duplicate address %s", addr)
		}
		m.handlers[addr] = gossip.Handler(filepath.Join(n.Dir, proven.MirrorDir), filepath.Join(n.Dir, "fork"))
		m.Nodes = append(m.Nodes, n)
	}
	return m, nil
}

// RoundTrip runs the real handler synchronously. An unknown address fails
// closed; it can never escape the simulation through the default transport.
func (m *Mesh) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	h := m.handlers[req.URL.Scheme+"://"+req.URL.Host]
	if h == nil {
		return nil, fmt.Errorf("sim: no peer at %s", req.URL.Host)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Result(), nil
}

// Cycle advances every clock, then runs nodes and their gossip rounds in
// index order. An optional subset lets a scenario deliver a head to one node
// before cutting the log. Results correspond to the selected node order.
func (m *Mesh) Cycle(delta time.Duration, indices ...int) []error {
	if delta < 0 {
		panic("sim: time cannot move backwards")
	}
	m.Elapsed += delta
	for _, n := range m.Nodes {
		n.Mono += delta
		n.Wall = n.Wall.Add(delta)
	}
	if len(indices) == 0 {
		for i := range m.Nodes {
			indices = append(indices, i)
		}
	}
	previous := gossip.SetTransport(m)
	defer gossip.SetTransport(previous)
	errs := make([]error, len(indices))
	for i, index := range indices {
		errs[i] = m.Nodes[index].Agent.Once()
	}
	return errs
}
