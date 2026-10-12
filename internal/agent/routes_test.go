package agent

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/endpoint"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/tlogstore"
)

// appendParams appends a root-signed `params` entry, as appendRevoke does a
// signer-signed revocation.
func appendParams(t *testing.T, store *tlogstore.Store, body map[string]any, after uint64) {
	t.Helper()
	doc := anchor(t)
	env := &entry.Envelope{
		Prev: storePrev(t, store, "params", ""), V: entry.Version, T: "params", Net: doc.Net, TS: 1_760_500_000, After: &after, Body: body,
	}
	for _, name := range []string{"root1", "root2", "root3"} {
		if err := entry.Sign(env, fixtureKey(t, name), "root"); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(raw); err != nil {
		t.Fatal(err)
	}
}

// advisoryLog is the fixture's log with a root-signed `params` entry naming
// `routes = "advisory"` appended: for the tests whose subject is not route
// authority (gossip addressing, overlaps, the own key, a reboot) and which
// give provider routes to devices the fixture enrolled with no grant. Under
// the default, D-073's, those devices source nothing, so the property each
// test is about would be invisible rather than tested.
func advisoryLog(t *testing.T) string {
	t.Helper()
	dir, store, entries := writableLog(t)
	appendParams(t, store, map[string]any{"routes": "advisory"}, uint64(len(entries)))
	return dir
}

func installed(t *testing.T, fake *peertable.Fake, id string) []string {
	t.Helper()
	peers, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range peertable.ByKey(peers)[keyOfDevice(t, id)].AllowedIPs {
		out = append(out, p.String())
	}
	return out
}

// D-073, §13.1. The one thing a compromised coordinator could still do: hand
// a legitimate peer `0.0.0.0/0`. `router` is enrolled with the grant
// `10.9.1.0/24, fd00::/64`; the provider offers that and the whole IPv4
// internet. Only the grant is installed, and the attempt is said.
func TestAProviderCannotWidenAPeersRoutes(t *testing.T) {
	fake := peertable.NewFake()
	fake.MaskPrefixes = true
	rec := &recorder{}
	a := newAgent(t, reconcile.Owner, servedLog(t), fake, rec)
	a.cfg.Provider = endpoint.Static{Peers: map[string]endpoint.Hints{
		"router": {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.1.0/24"), netip.MustParsePrefix("0.0.0.0/0")}},
	}}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := installed(t, fake, "router"); strings.Join(got, ",") != "10.9.1.0/24" {
		t.Errorf("router was installed with %v; the grant is 10.9.1.0/24", got)
	}
	var said bool
	for _, e := range rec.events {
		if e.Kind == ProviderClaim && strings.Contains(e.Message, "0.0.0.0/0") && strings.Contains(e.Message, "router") {
			said = true
		}
	}
	if !said {
		t.Errorf("the widened prefix was withheld silently: %v", rec.kinds())
	}
}

// A device enrolled without a grant is installed with its key and no routes,
// whatever the provider offers, and the node says so once per device, not
// every T_poll.
func TestADeviceWithNoGrantIsInstalledKeyOnlyAndSaidOnce(t *testing.T) {
	fake := peertable.NewFake()
	rec := &recorder{}
	a := newAgent(t, reconcile.Owner, servedLog(t), fake, rec)
	a.cfg.Provider = endpoint.Static{Peers: map[string]endpoint.Hints{
		"nas": {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/32")}},
	}}
	for i := 0; i < 50; i++ {
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
	}
	if got := installed(t, fake, "nas"); len(got) != 0 {
		t.Errorf("nas has no grant and was installed with %v", got)
	}
	if !holds(mustPeers(t, fake), keyOfDevice(t, "nas")) {
		t.Error("a proven device with no grant lost its key, not just its routes")
	}
	var nas int
	for _, e := range rec.events {
		if e.Kind == RoutesUngranted && strings.Contains(e.Message, `"nas"`) {
			nas++
		}
	}
	if nas != 1 {
		t.Errorf("nas's missing grant was said %d times in 50 cycles, want once", nas)
	}
}

// `params.routes = "advisory"` is D-026's reading, kept for a network that
// asks for it in its genesis or by a root-signed `params`: the provider's
// prefixes are installed as given, and nothing is said about grants.
func TestAdvisoryRoutesInstallTheProvidersRoutesAsGiven(t *testing.T) {
	dir, store, entries := writableLog(t)
	appendParams(t, store, map[string]any{"routes": "advisory"}, uint64(len(entries)))
	fake := peertable.NewFake()
	rec := &recorder{}
	a := newAgent(t, reconcile.Owner, dir, fake, rec)
	a.cfg.Provider = endpoint.Static{Peers: map[string]endpoint.Hints{
		"nas": {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/32")}},
	}}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := installed(t, fake, "nas"); strings.Join(got, ",") != "10.9.0.1/32" {
		t.Errorf("under advisory routes nas was installed with %v, want the provider's 10.9.0.1/32", got)
	}
	if rec.kinds()[RoutesUngranted] != 0 {
		t.Errorf("advisory routes have no grants to miss: %v", rec.kinds())
	}
}

func mustPeers(t *testing.T, fake *peertable.Fake) []peertable.Peer {
	t.Helper()
	peers, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	return peers
}
