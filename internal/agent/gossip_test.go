package agent

import (
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
	handler := gossip.Handler(dir)
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

// A node with a healthy log does not need its peers, and asking them anyway
// would put a poll on every neighbour on every cycle of every node -- which on
// a 200 ms poll is a lot of traffic to protect against nothing.
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
	if asked() != 0 {
		t.Errorf("peers were polled %d times while the log was answering", asked())
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
	peerURL, asked := peerServing(t, full)

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
		t.Error("peers were asked while the view was fresh")
	}

	// Time passes and nothing new is cosigned: the view goes stale even though
	// the log is answering every request.
	mono = 20 * time.Minute
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}

	if asked() == 0 {
		t.Fatal("a degraded node did not ask its peers; the mesh would stay stale " +
			"behind a log that never stopped answering")
	}
	if a.last.Checkpoint.Size != 90 {
		t.Errorf("size = %d, want the peer's 90", a.last.Checkpoint.Size)
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
