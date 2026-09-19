package wgdev

import (
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/onembyte/norn/internal/peertable"
)

func key(t *testing.T, b byte) peertable.Key {
	t.Helper()
	var k peertable.Key
	for i := range k {
		k[i] = b
	}
	return k
}

// The conversions are where a silent mistake becomes a security or
// availability bug, so they are tested as functions rather than through a
// kernel nobody has in CI.
func TestKeysSurviveTheConversion(t *testing.T) {
	mine := key(t, 0x42)
	theirs := wgtypes.Key(mine)
	if theirs.String() != mine.String() {
		t.Errorf("wgctrl renders the key as %q, Norn as %q", theirs.String(), mine.String())
	}
	if peertable.Key(theirs) != mine {
		t.Error("the key did not survive the round trip")
	}
}

// The property from 3.2, at the layer that finally touches a kernel: no
// endpoint means "leave it alone", not "clear it". Getting this wrong takes a
// roaming peer offline until it happens to handshake again.
func TestNoEndpointMeansLeaveItAlone(t *testing.T) {
	config := toWG(peertable.Peer{Key: key(t, 1)}, false)
	if config.Endpoint != nil {
		t.Error("an absent endpoint became an instruction to change it")
	}
	if config.PersistentKeepaliveInterval != nil {
		t.Error("an absent keepalive became an instruction to change it")
	}

	withEndpoint := peertable.Peer{Key: key(t, 1), Keepalive: 25 * time.Second,
		Endpoint: netip.MustParseAddrPort("192.0.2.7:51820")}
	config = toWG(withEndpoint, false)
	if config.Endpoint == nil || config.Endpoint.String() != "192.0.2.7:51820" {
		t.Errorf("endpoint = %v", config.Endpoint)
	}
	if config.PersistentKeepaliveInterval == nil || *config.PersistentKeepaliveInterval != 25*time.Second {
		t.Errorf("keepalive = %v", config.PersistentKeepaliveInterval)
	}
}

// Allowed-ips are authority: they are set exactly, never added to, or an entry
// Norn did not put there would survive a rewrite.
func TestAllowedIPsAreReplacedNotAdded(t *testing.T) {
	peer := peertable.Peer{Key: key(t, 1), AllowedIPs: []netip.Prefix{
		netip.MustParsePrefix("10.9.0.1/32"), netip.MustParsePrefix("fd00::1/128")}}

	config := toWG(peer, false)
	if !config.ReplaceAllowedIPs {
		t.Fatal("a rewrite that adds to the allowed-ips leaves an intruder's routes in place")
	}
	if len(config.AllowedIPs) != 2 {
		t.Fatalf("allowed-ips = %+v", config.AllowedIPs)
	}
	if config.AllowedIPs[0].String() != "10.9.0.1/32" || config.AllowedIPs[1].String() != "fd00::1/128" {
		t.Errorf("allowed-ips = %v and %v", config.AllowedIPs[0].String(), config.AllowedIPs[1].String())
	}
}

// A refresh must not touch routing at all.
func TestAnUpdateCarriesNoRoutes(t *testing.T) {
	peer := peertable.Peer{Key: key(t, 1),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/32")},
		Endpoint:   netip.MustParseAddrPort("192.0.2.7:51820")}

	config := toWG(peer, true)
	if !config.UpdateOnly {
		t.Error("a refresh must be UpdateOnly, or it adds keys")
	}
	if config.ReplaceAllowedIPs || len(config.AllowedIPs) != 0 {
		t.Error("a refresh rewrote the routing")
	}
	if config.Endpoint == nil {
		t.Error("a refresh carried no endpoint, which is all it is for")
	}
}

func TestPeersComeBackTheWayTheyWentIn(t *testing.T) {
	endpoint := netip.MustParseAddrPort("198.51.100.4:51820")
	reported := wgtypes.Peer{
		PublicKey: wgtypes.Key(key(t, 3)),
		AllowedIPs: []net.IPNet{
			{IP: net.ParseIP("10.9.0.4").To4(), Mask: net.CIDRMask(32, 32)},
		},
		Endpoint:                    net.UDPAddrFromAddrPort(endpoint),
		PersistentKeepaliveInterval: 25 * time.Second,
	}

	got := fromWG(reported)
	if got.Key != key(t, 3) {
		t.Error("the key changed")
	}
	if len(got.AllowedIPs) != 1 || got.AllowedIPs[0].String() != "10.9.0.4/32" {
		t.Errorf("allowed-ips = %+v", got.AllowedIPs)
	}
	if got.Endpoint != endpoint {
		t.Errorf("endpoint = %v, want %v", got.Endpoint, endpoint)
	}
	if got.Keepalive != 25*time.Second {
		t.Errorf("keepalive = %v", got.Keepalive)
	}
}

// A v4 endpoint arrives from the kernel as a 16-byte mapped address; it must
// come back as 192.0.2.1:51820, not ::ffff:192.0.2.1.
func TestAMappedV4EndpointIsUnmapped(t *testing.T) {
	reported := wgtypes.Peer{
		PublicKey: wgtypes.Key(key(t, 4)),
		Endpoint:  &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820},
	}
	got := fromWG(reported)
	if got.Endpoint.String() != "192.0.2.1:51820" {
		t.Errorf("endpoint = %q", got.Endpoint.String())
	}
	if !got.Endpoint.Addr().Is4() {
		t.Error("a v4 endpoint did not come back as v4")
	}
}

func TestOpeningAnInterfaceThatIsNotThere(t *testing.T) {
	if _, err := Open("norn-does-not-exist0"); err == nil {
		t.Fatal("opened an interface that does not exist")
	}
}

// If a WireGuard interface happens to exist, read it: on a developer's machine
// or a lab box this is the only test that touches a kernel.
func TestAgainstARealInterfaceIfOneExists(t *testing.T) {
	out, err := exec.Command("wg", "show", "interfaces").Output()
	if err != nil {
		t.Skip("the wg tool is not installed; nothing to read")
	}
	names := strings.Fields(string(out))
	if len(names) == 0 {
		t.Skip("no WireGuard interface on this machine")
	}

	device, err := Open(names[0])
	if err != nil {
		t.Fatalf("opening %s: %v", names[0], err)
	}
	defer device.Close()

	peers, err := device.Peers()
	if err != nil {
		t.Fatalf("reading %s: %v", names[0], err)
	}
	t.Logf("%s has %d peer(s)", names[0], len(peers))
	for _, peer := range peers {
		if peer.Key == (peertable.Key{}) {
			t.Error("a peer came back with a zero key")
		}
	}
}
