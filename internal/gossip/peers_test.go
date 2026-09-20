package gossip

import (
	"math/rand"
	"net/netip"
	"testing"
)

// `GOSSIP.md` part 6: "Every T_g a node pulls /norn/checkpoint from r = 3
// random proven peers". Two words there are load-bearing -- **random**,
// because a fixed order lets one peer decide what a node hears, and
// **proven**, because an unproven peer is not somebody this network vouches
// for.

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

func TestAPeerIsReachedAtItsTunnelAddress(t *testing.T) {
	got, ok := Address(prefixes(t, "10.9.0.42/32"), 8100)
	if !ok {
		t.Fatal("a peer with an allowed-ip has an address")
	}
	if got != "http://10.9.0.42:8100" {
		t.Errorf("address = %q", got)
	}

	// IPv6 gets its brackets, or the URL is nonsense.
	got, ok = Address(prefixes(t, "fd00::42/128"), 8100)
	if !ok {
		t.Fatal("an IPv6 peer has an address too")
	}
	if got != "http://[fd00::42]:8100" {
		t.Errorf("address = %q", got)
	}
}

// A peer routed a whole subnet is reached at the subnet's own address rather
// than skipped: `10.9.0.0/24` is a route, and its first address is as good a
// guess as exists. A peer with no allowed-ips at all cannot be reached.
func TestAPeerWithNoAddressIsNotReachable(t *testing.T) {
	if _, ok := Address(nil, 8100); ok {
		t.Error("an address was produced for a peer with no allowed-ips")
	}
}

func TestChooseTakesAtMostRPeers(t *testing.T) {
	all := []string{"a", "b", "c", "d", "e"}
	source := rand.New(rand.NewSource(1))

	got := Choose(all, 3, source)
	if len(got) != 3 {
		t.Fatalf("chose %d peers, want 3", len(got))
	}
	seen := map[string]bool{}
	for _, peer := range got {
		if seen[peer] {
			t.Errorf("%s was chosen twice in one round", peer)
		}
		seen[peer] = true
	}

	// Fewer peers than r is everybody, not an error.
	if got := Choose(all[:2], 3, source); len(got) != 2 {
		t.Errorf("chose %d of 2 peers", len(got))
	}
	if got := Choose(nil, 3, source); len(got) != 0 {
		t.Errorf("chose %d peers from none", len(got))
	}
}

// Random, not fixed. A node that always asked the same three peers would let
// those three decide what the rest of the mesh hears -- and in a network small
// enough to fit in a house, "the same three" is often "all the ones the
// attacker owns".
func TestChooseIsNotAFixedOrder(t *testing.T) {
	all := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	source := rand.New(rand.NewSource(7))

	first := Choose(all, 3, source)
	for i := 0; i < 20; i++ {
		if got := Choose(all, 3, source); !sameOrder(got, first) {
			return // it varies, which is the point
		}
	}
	t.Errorf("twenty rounds all chose %v; a fixed order lets those peers decide "+
		"what this node hears", first)
}

func sameOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
