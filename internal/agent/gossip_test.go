package agent

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/endpoint"
	"github.com/onembyte/norn/internal/freshness"
	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/tlogstore"
)

// `GOSSIP.md` part 6: every T_g a node pulls from r random **proven** peers and
// runs the same verification on what comes back. A peer is a second source,
// not a second trust model -- which is why this file tests where a node looks
// and what it does with the answer, and not one line of new verification.

// peerServing stands up a gossip server over a log directory and returns its
// URL and a counter of how many times it was asked.
func peerServing(t *testing.T, dir string) (string, func() int) {
	t.Helper()
	var mu sync.Mutex
	var asked int
	handler := gossip.Handler(dir, "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/checkpoint") {
			mu.Lock()
			asked++
			mu.Unlock()
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server.URL, func() int {
		mu.Lock()
		defer mu.Unlock()
		return asked
	}
}

// The property gossip exists for (T2): the log is unreachable, and a peer that
// has the log carries the node through.
func TestAPeerCarriesTheNodeWhenTheLogIsGone(t *testing.T) {
	full, _, _ := writableLog(t)
	peerURL, asked := peerServing(t, full)

	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(t.TempDir()), // an empty, dead "log"
		Device: peertable.NewFake(), Mode: reconcile.Owner, Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:  func() time.Duration { return 0 },
		Peers: func() []string { return []string{peerURL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatalf("a node with a dead log and a healthy peer should recover: %v", err)
	}

	if asked() == 0 {
		t.Error("the peer was never asked")
	}
	if a.last == nil || a.last.Checkpoint.Size == 0 {
		t.Fatal("nothing was adopted from the peer")
	}
	if rec.kinds()[AdoptedFromPeer] != 1 {
		t.Errorf("adopting another node's checkpoint should be said out loud: %v",
			rec.kinds())
	}
}

// A peer offering an older view is refused by §10's stored-head check (4.5c),
// and the node keeps what it had. This is the case that makes gossip safe to
// have at all.
func TestAPeerCannotRollANodeBack(t *testing.T) {
	full, _, entries := writableLog(t)
	short := shorterLog(t, entries[:len(entries)/2])
	peerURL, _ := peerServing(t, short)

	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: peertable.NewFake(),
		Mode: reconcile.Owner, Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:  func() time.Duration { return 0 },
		Peers: func() []string { return []string{peerURL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	held := a.last.Checkpoint.Size

	// The log goes away; only the rolled-back peer is left.
	a.cfg.Fetcher = logclient.Dir(t.TempDir())
	_ = a.Once()

	if a.last.Checkpoint.Size != held {
		t.Errorf("a peer rolled this node back from %d to %d entries",
			held, a.last.Checkpoint.Size)
	}
}

// A peer that answers with nonsense must not break the cycle: the node has a
// log and other peers, and one broken neighbour is not an outage.
func TestABrokenPeerIsSurvivable(t *testing.T) {
	full, _, _ := writableLog(t)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not a checkpoint"))
	}))
	t.Cleanup(broken.Close)

	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: peertable.NewFake(),
		Mode: reconcile.Owner, Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:  func() time.Duration { return 0 },
		Peers: func() []string { return []string{broken.URL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatalf("a broken peer broke the cycle: %v", err)
	}
	if a.last == nil {
		t.Error("the log's own checkpoint was lost because a peer misbehaved")
	}
}

// A healthy log does not cause peer requests on every local poll. The separate
// gossip cadence is checked below.
func TestPeersAreNotAskedWhenTheLogAnswers(t *testing.T) {
	full, _, _ := writableLog(t)
	peerURL, asked := peerServing(t, full)

	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: peertable.NewFake(),
		Mode: reconcile.Observe, Emit: (&recorder{}).emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:  func() time.Duration { return 0 },
		Peers: func() []string { return []string{peerURL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
	}
	// Exactly one round: the first head's corroboration (D-071 c), in the
	// cycle it verified. A healthy log is no reason for any other before T_g.
	if asked() != 1 {
		t.Errorf("peers were polled %d times before the first gossip interval; "+
			"want only the first head's corroboration", asked())
	}
}

func TestPeerCheckpointDoesNotTriggerClockSkew(t *testing.T) {
	full, _, _ := writableLog(t)
	peerURL, _ := peerServing(t, full)
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(t.TempDir()),
		Device: peertable.NewFake(), Mode: reconcile.Observe, Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(2 * time.Hour) },
		Mono:  func() time.Duration { return 0 },
		Peers: func() []string { return []string{peerURL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := rec.kinds()[ClockSkew]; got != 0 {
		t.Errorf("peer checkpoint triggered %d clock-skew alarms", got)
	}
}

// A healthy log is not proof that another node sees the same history. Ask
// proven peers on the gossip cadence, without turning a 200 ms local poll into
// a 200 ms network poll.
func TestHealthyLogChecksPeerCheckpointAtGossipInterval(t *testing.T) {
	full, _, _ := writableLog(t)
	peerURL, asked := peerServing(t, full)
	var mono time.Duration
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: peertable.NewFake(),
		Mode: reconcile.Observe, Emit: (&recorder{}).emit,
		Now:         func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(mono) },
		Mono:        func() time.Duration { return mono },
		Peers:       func() []string { return []string{peerURL} },
		GossipEvery: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The request at 0 s is the first head's corroboration (D-071 c); from
	// then on the cadence is T_g.
	for _, tc := range []struct {
		at   time.Duration
		want int
	}{
		{0, 1}, {29 * time.Second, 1}, {30 * time.Second, 2},
		{31 * time.Second, 2}, {60 * time.Second, 3},
	} {
		mono = tc.at
		if err := a.Once(); err != nil {
			t.Fatalf("cycle at %s: %v", mono, err)
		}
		if got := asked(); got != tc.want {
			t.Errorf("checkpoint requests at %s = %d, want %d", mono, got, tc.want)
		}
	}
}

var _ = cosign.Append
var _ = tlogstore.Open

// "Unproven peers are not polled" (GOSSIP part 6). The addresses a node
// gossips to come from the proven set and nowhere else: an unproven key on the
// interface is exactly what Norn exists to notice, and asking it for a
// checkpoint would be asking the intruder what the network looks like.
func TestOnlyProvenPeersAreAddressed(t *testing.T) {
	full, _, _ := writableLog(t)
	fake := peertable.NewFake()

	// The operator has written routes for a proven device *and* for an
	// intruder -- so the only thing keeping the intruder out of the gossip
	// round is that the log does not prove it.
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: fake,
		Mode: reconcile.Owner, Emit: (&recorder{}).emit,
		Provider: endpoint.Static{Peers: map[string]endpoint.Hints{
			"nas":      {AllowedIPs: prefixes(t, "10.9.0.2/32")},
			"pi-cam":   {AllowedIPs: prefixes(t, "10.9.0.3/32")},
			"intruder": {AllowedIPs: prefixes(t, "10.99.0.1/32")},
		}},
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}

	addresses := a.PeerAddresses(8100)
	if len(addresses) != 2 {
		t.Fatalf("addresses = %v, want the two routed proven devices", addresses)
	}
	for _, addr := range addresses {
		if strings.Contains(addr, "10.99.") {
			t.Errorf("%s belongs to a device the log does not prove; unproven peers "+
				"are not polled, and asking one would be asking the intruder what "+
				"the network looks like", addr)
		}
	}
}

// A proven peer the operator has written no route for cannot be reached, and
// Norn does not invent an address for it.
func TestAnUnroutedPeerIsNotAddressed(t *testing.T) {
	full, _, _ := writableLog(t)
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: peertable.NewFake(),
		Mode: reconcile.Observe, Emit: (&recorder{}).emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := a.PeerAddresses(8100); len(got) != 0 {
		t.Errorf("addresses = %v for devices with no routes", got)
	}
}

func prefixes(t *testing.T, texts ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, text := range texts {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, prefix)
	}
	return out
}

// `GOSSIP.md` part 5: a degraded node polls **all sources** every 10 s.
//
// The part that matters is not the number, it is "all sources". A node whose
// log is answering perfectly well with something *old* is exactly the node
// that needs to ask its peers -- the log is up and stuck, which is what T2
// describes, and only a peer can tell it so. Asking peers only when the log is
// unreachable would leave the whole mesh stale behind a log that never stopped
// answering.
func TestADegradedNodeAsksItsPeersEvenWhenTheLogAnswers(t *testing.T) {
	full, _, entries := writableLog(t)
	stuck := shorterLog(t, entries[:45])
	// The peer is as stuck as the log while the node starts, so the first head
	// is corroborated at 45 (D-071 c); a peer that already had more would be
	// adopted in that first cycle, which is the point of corroborating.
	stuckPeerURL, _ := peerServing(t, stuck)
	fullPeerURL, asked := peerServing(t, full)
	peerURL := stuckPeerURL

	var mono time.Duration
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(stuck), Device: peertable.NewFake(),
		Mode: reconcile.Owner, Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(mono) },
		Mono:  func() time.Duration { return mono },
		Peers: func() []string { return []string{peerURL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if a.last.Checkpoint.Size != 45 {
		t.Fatalf("size = %d, want the stuck log's 45", a.last.Checkpoint.Size)
	}
	if asked() != 0 {
		t.Error("the peer with more was asked while the view was fresh")
	}

	// Time passes and nothing new is cosigned: the view goes stale even though
	// the log is answering every request. The peer, meanwhile, has moved on.
	peerURL = fullPeerURL
	mono = 20 * time.Minute
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}

	if asked() == 0 {
		t.Fatal("a degraded node did not ask its peers; the mesh would stay stale " +
			"behind a log that never stopped answering")
	}
	if want := int64(len(entries)); a.last.Checkpoint.Size != want {
		t.Errorf("size = %d, want the peer's %d", a.last.Checkpoint.Size, want)
	}
	if rec.kinds()[AdoptedFromPeer] == 0 {
		t.Error("adopting from a peer should be said out loud")
	}
}

// And a peer with nothing newer changes nothing: a degraded node that took a
// peer's equal-size checkpoint would churn its peer table for no reason.
func TestADegradedNodeIgnoresAPeerWithNothingNewer(t *testing.T) {
	full, _, _ := writableLog(t)
	peerURL, asked := peerServing(t, full)

	var mono time.Duration
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: peertable.NewFake(),
		Mode: reconcile.Owner, Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(mono) },
		Mono:  func() time.Duration { return mono },
		Peers: func() []string { return []string{peerURL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	mono = 20 * time.Minute
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}

	if asked() == 0 {
		t.Error("a degraded node should still ask")
	}
	if rec.kinds()[AdoptedFromPeer] != 0 {
		t.Error("a peer with the same head is not an adoption")
	}
}

// A daemon needs to know when to try harder, and a node that only reported
// freshness in a file nobody was watching would carry on at its leisurely poll
// through an outage.
func TestFreshnessIsReadableByTheDaemon(t *testing.T) {
	full, _, _ := writableLog(t)
	var mono time.Duration
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: peertable.NewFake(),
		Mode: reconcile.Observe, Emit: (&recorder{}).emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(mono) },
		Mono: func() time.Duration { return mono },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Before the first cycle a node knows nothing, and says so rather than
	// claiming to be fresh.
	if got := a.Freshness(); got != freshness.Unknown {
		t.Errorf("freshness before the first cycle = %q, want %q", got, freshness.Unknown)
	}

	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := a.Freshness(); got != freshness.Fresh {
		t.Errorf("freshness = %q, want %q", got, freshness.Fresh)
	}

	mono = 20 * time.Minute
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := a.Freshness(); got != freshness.Degraded {
		t.Errorf("freshness = %q, want %q", got, freshness.Degraded)
	}
}

// T5's other half, and the reason the audit went looking: "proven set
// unchanged". A node whose wall clock is two hours out must enforce exactly
// the same peers -- which is only true if expiry is judged against the
// checkpoint's time rather than the machine's (§5.3, A11).
func TestASkewedClockDoesNotChangeTheProvenSet(t *testing.T) {
	full, _, _ := writableLog(t)
	right := peertable.NewFake()
	honest, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: right,
		Mode: reconcile.Owner, Emit: (&recorder{}).emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := honest.Once(); err != nil {
		t.Fatal(err)
	}
	expected, _ := right.Peers()

	// The same network, on a machine whose clock is a year fast -- which is
	// past the fixture's expiring device.
	skewed := peertable.NewFake()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: skewed,
		Mode: reconcile.Owner, Emit: (&recorder{}).emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt+365*24*3600, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	got, _ := skewed.Peers()

	if len(got) != len(expected) {
		t.Errorf("a wrong local clock changed the peer table: %d peers instead of %d. "+
			"Expiry is judged against the checkpoint's time, not this machine's.",
			len(got), len(expected))
	}
}

// SEC-003 (H2-a), the finding four auditors reproduced: a proven peer that
// accepts TCP and never answers held `Once()` forever, and with it eviction
// and every alarm. Watchdog mode, a healthy log, one unproven key installed,
// three silent peers: the cycle must still end and the key must still go.
func TestASilentPeerDoesNotStallEnforcement(t *testing.T) {
	was := gossip.FetchTimeout()
	gossip.SetTimeout(300 * time.Millisecond)
	t.Cleanup(func() { gossip.SetTimeout(was) })

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
	silent := "http://" + l.Addr().String()

	rec := &recorder{}
	fake := peertable.NewFake(provenKeys(t)...)
	fake.Inject(rogue(t))
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(servedLog(t)), Device: fake,
		Mode: reconcile.Watchdog, Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:  func() time.Duration { return 0 },
		Peers: func() []string { return []string{silent, silent, silent} },
	})
	if err != nil {
		t.Fatal(err)
	}

	finished := make(chan error, 1)
	go func() { finished <- a.Once() }()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("the cycle failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Once() is still blocked on a silent peer after 10s; before SEC-003 it never returned")
	}
	peers, _ := fake.Peers()
	for _, peer := range peers {
		if peer.Key == rogue(t).Key {
			t.Fatal("the rogue key survived a watchdog cycle that a silent peer delayed")
		}
	}
}

// SEC-035 (row 035-ii): an overlap the provider created is said out loud, as
// every other provider fault is. A route withheld in silence would look, to
// the operator, like a peer Norn broke.
func TestOverlappingRoutesAreReportedAsAProviderClaim(t *testing.T) {
	full, _, _ := writableLog(t)
	rec := &recorder{}
	fake := peertable.NewFake()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(full), Device: fake,
		Mode: reconcile.Owner, Emit: rec.emit,
		Provider: endpoint.Static{Peers: map[string]endpoint.Hints{
			"nas":    {AllowedIPs: prefixes(t, "10.9.0.0/24")},
			"pi-cam": {AllowedIPs: prefixes(t, "10.9.0.3/32")},
		}},
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	said := false
	for _, e := range rec.events {
		if e.Kind == ProviderClaim && strings.Contains(e.Message, "overlap") &&
			strings.Contains(e.Message, "nas") && strings.Contains(e.Message, "pi-cam") {
			said = true
		}
	}
	if !said {
		t.Errorf("the overlap was not reported: %v", rec.kinds())
	}
	peers, _ := fake.Peers()
	for _, peer := range peers {
		for _, prefix := range peer.AllowedIPs {
			if prefix.Overlaps(netip.MustParsePrefix("10.9.0.3/32")) {
				t.Errorf("an overlapping route was installed: %v", prefix)
			}
		}
	}
}
