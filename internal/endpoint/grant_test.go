package endpoint

import (
	"net/netip"
	"strings"
	"testing"
)

func prefixes(t *testing.T, texts ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(texts))
	for _, text := range texts {
		out = append(out, netip.MustParsePrefix(text))
	}
	return out
}

// D-073. A peer's allowed-ips is its authority to source those addresses,
// so under `routes = "granted"` a provider's prefix is installed only where
// it lies within the device's grant: a provider may narrow a grant and never
// widen it, and what it tried to widen is said.
func TestAGrantBoundsTheProvidersRoutes(t *testing.T) {
	router := device(t, "router", 1, nil)
	router.Grant = prefixes(t, "10.9.1.0/24", "fd00::/64")
	provider := Static{Peers: map[string]Hints{"router": {AllowedIPs: prefixes(t,
		"10.9.1.7/32",   // inside the IPv4 grant
		"10.9.1.0/24",   // the grant itself
		"10.9.0.0/16",   // contains the grant: wider
		"10.9.2.0/24",   // beside it
		"fd00::1/128",   // inside the IPv6 grant
		"fd00::/48",     // wider
		"2001:db8::/32", // elsewhere
	)}}}
	peers, report := DesiredGranted([]Device{router}, provider)
	if len(peers) != 1 {
		t.Fatalf("%d peers, want the one proven device", len(peers))
	}
	var got []string
	for _, p := range peers[0].AllowedIPs {
		got = append(got, p.String())
	}
	if want := "10.9.1.7/32,10.9.1.0/24,fd00::1/128"; strings.Join(got, ",") != want {
		t.Errorf("installed %v, want only the prefixes within the grant (%s)", got, want)
	}
	if want := "router 10.9.0.0/16,router 10.9.2.0/24,router fd00::/48,router 2001:db8::/32"; strings.Join(report.Widened, ",") != want {
		t.Errorf("widened = %v, want %s", report.Widened, want)
	}
	if len(report.Ungranted) != 0 || len(report.Unrouted) != 0 {
		t.Errorf("a granted, routed device was reported as %+v", report)
	}
}

// A proven device with no grant is still a peer -- the log vouches for its
// key -- but it sources nothing: its key is installed with no allowed-ips,
// whatever the provider offered, and the device is reported as ungranted.
func TestADeviceWithNoGrantGetsItsKeyOnly(t *testing.T) {
	nas := device(t, "nas", 2, nil)
	provider := Static{Peers: map[string]Hints{"nas": {AllowedIPs: prefixes(t, "10.9.0.1/32")}}}
	peers, report := DesiredGranted([]Device{nas}, provider)
	if len(peers) != 1 || len(peers[0].AllowedIPs) != 0 {
		t.Fatalf("peers = %v; want nas with its key and no allowed-ips", peers)
	}
	if strings.Join(report.Ungranted, ",") != "nas" {
		t.Errorf("ungranted = %v, want nas", report.Ungranted)
	}
	if len(report.Widened) != 0 {
		t.Errorf("a device with no grant has nothing to widen: %v", report.Widened)
	}
}
