package peertable

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func key(t *testing.T, b byte) Key {
	t.Helper()
	var k Key
	for i := range k {
		k[i] = b
	}
	return k
}

func prefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Keys round-trip through WireGuard's own encoding, so a key printed by Norn
// can be pasted into `wg` and compared against `wg show` without translation.
func TestKeyEncoding(t *testing.T) {
	k := key(t, 0xab)
	parsed, err := ParseKey(k.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != k {
		t.Error("a key did not survive its own encoding")
	}
	if len(k.String()) != 44 || !strings.HasSuffix(k.String(), "=") {
		t.Errorf("not WireGuard's base64: %q", k.String())
	}
	if !strings.HasSuffix(k.Short(), "…") || len(k.Short()) > 12 {
		t.Errorf("Short is for logs: %q", k.Short())
	}

	for _, bad := range []string{"", "not base64!!", "c2hvcnQ="} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("accepted %q as a key", bad)
		}
	}
	if _, err := KeyFromBytes(make([]byte, 31)); err == nil {
		t.Error("accepted a 31-byte key")
	}
}

// Routing is the key and its allowed-ips. Endpoint and keepalive are excluded
// deliberately: a roaming peer must not look like a security event.
func TestSameRoutingIgnoresReachability(t *testing.T) {
	base := Peer{Key: key(t, 1), AllowedIPs: []netip.Prefix{prefix(t, "10.9.0.1/32")}}
	roamed := base
	roamed.Endpoint = netip.MustParseAddrPort("192.0.2.9:51820")
	roamed.Keepalive = 25 * time.Second

	if !base.SameRouting(roamed) {
		t.Error("a changed endpoint changed the routing")
	}
	if base.SameEndpoint(roamed) {
		t.Error("a changed endpoint is still a change")
	}

	wider := base
	wider.AllowedIPs = []netip.Prefix{prefix(t, "10.9.0.0/24")}
	if base.SameRouting(wider) {
		t.Error("a widened allowed-ips must count as different routing")
	}

	other := base
	other.Key = key(t, 2)
	if base.SameRouting(other) {
		t.Error("different keys are different peers")
	}
}

func TestAllowedIPsOrderDoesNotMatter(t *testing.T) {
	a := Peer{Key: key(t, 1), AllowedIPs: []netip.Prefix{
		prefix(t, "10.9.0.1/32"), prefix(t, "fd00::1/128")}}
	b := Peer{Key: key(t, 1), AllowedIPs: []netip.Prefix{
		prefix(t, "fd00::1/128"), prefix(t, "10.9.0.1/32")}}
	if !a.SameRouting(b) {
		t.Error("the same routes in another order are the same routes")
	}
}

func TestFakeRecordsWhatTheInterfaceWasTold(t *testing.T) {
	one := Peer{Key: key(t, 1)}
	two := Peer{Key: key(t, 2)}
	fake := NewFake(one)

	if err := fake.Replace([]Peer{one, two}); err != nil {
		t.Fatal(err)
	}
	peers, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("%d peers after a replace", len(peers))
	}
	if err := fake.Remove([]Key{two.Key}); err != nil {
		t.Fatal(err)
	}
	peers, _ = fake.Peers()
	if len(peers) != 1 || peers[0].Key != one.Key {
		t.Fatalf("remove left %+v", peers)
	}

	// The record distinguishes acts with the same outcome: rewriting the whole
	// table and removing one key are different modes.
	if len(fake.Calls) != 2 || fake.Calls[0].Op != "replace" || fake.Calls[1].Op != "remove" {
		t.Errorf("calls = %+v", fake.Calls)
	}
	if fake.Writes() != 2 {
		t.Errorf("Writes = %d", fake.Writes())
	}
}

// UpdateOnly refreshes; it does not add. A fake that quietly added a key would
// hide a bug the kernel would have caught.
func TestUpdateEndpointsRefusesToAdd(t *testing.T) {
	present := Peer{Key: key(t, 1)}
	fake := NewFake(present)

	roamed := present
	roamed.Endpoint = netip.MustParseAddrPort("192.0.2.1:51820")
	if err := fake.UpdateEndpoints([]Peer{roamed}); err != nil {
		t.Fatal(err)
	}
	peers, _ := fake.Peers()
	if peers[0].Endpoint != roamed.Endpoint {
		t.Error("the endpoint was not refreshed")
	}

	absent := Peer{Key: key(t, 9)}
	if err := fake.UpdateEndpoints([]Peer{absent}); err == nil {
		t.Error("UpdateEndpoints added a key that was not there")
	}
}

func TestFakeKeepsPresharedKeysAcrossReadsRewritesAndEndpointUpdates(t *testing.T) {
	current := Peer{Key: key(t, 1)}
	current.PresharedKey[0] = 7
	fake := NewFake(current)
	check := func() {
		t.Helper()
		peers, err := fake.Peers()
		if err != nil {
			t.Fatal(err)
		}
		if len(peers) != 1 || peers[0].PresharedKey != current.PresharedKey {
			t.Error("the fake table lost the preshared key")
		}
	}
	check()
	if err := fake.Replace([]Peer{current}); err != nil {
		t.Fatal(err)
	}
	check()
	refresh := Peer{Key: current.Key, Endpoint: netip.MustParseAddrPort("192.0.2.1:51820")}
	if err := fake.UpdateEndpoints([]Peer{refresh}); err != nil {
		t.Fatal(err)
	}
	check()
}

// Inject is how a test plays the other writer: a key appears without Norn
// having asked for it, which is the whole situation watchdog mode exists for.
func TestInjectDoesNotLookLikeANornWrite(t *testing.T) {
	fake := NewFake()
	fake.Inject(Peer{Key: key(t, 7)})

	peers, _ := fake.Peers()
	if len(peers) != 1 {
		t.Fatalf("%d peers", len(peers))
	}
	if fake.Writes() != 0 {
		t.Error("an injected peer was recorded as a write Norn made")
	}
}

func TestAnInterfaceThatIsDown(t *testing.T) {
	fake := NewFake()
	fake.FailPeers = ErrDown
	if _, err := fake.Peers(); err == nil {
		t.Error("read from an interface that is down")
	}
	fake.FailPeers = nil
	fake.FailWrite = ErrDown
	if err := fake.Replace(nil); err == nil {
		t.Error("wrote to an interface that is down")
	}
	if fake.Writes() != 0 {
		t.Error("a failed write was recorded as a write")
	}
}

func TestByKeyAndSorted(t *testing.T) {
	peers := []Peer{{Key: key(t, 3)}, {Key: key(t, 1)}, {Key: key(t, 2)}}
	indexed := ByKey(peers)
	if len(indexed) != 3 {
		t.Fatalf("%d keys", len(indexed))
	}
	sorted := Sorted(peers)
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].Key.String() > sorted[i].Key.String() {
			t.Fatal("Sorted did not sort")
		}
	}
}
