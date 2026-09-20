package gossip

import (
	"math/rand"
	"net"
	"net/netip"
	"strconv"
)

// DefaultFanout is `GOSSIP.md`'s `r = 3`: how many peers a node asks per round.
//
// Three is enough that one silent or lying peer does not decide what a node
// hears, and few enough that a round costs almost nothing on a link that is
// also carrying the traffic this is protecting.
const DefaultFanout = 3

// Address is where a peer's gossip server can be reached: its tunnel address,
// which is the one address this network can vouch for, because it is the one
// the log put in that peer's allowed-ips.
//
// A peer routed a whole subnet is reached at the subnet's own address -- a
// route's first address is as good a guess as exists -- and a peer with no
// allowed-ips cannot be reached at all.
func Address(allowedIPs []netip.Prefix, port int) (string, bool) {
	for _, prefix := range allowedIPs {
		addr := prefix.Addr()
		if !addr.IsValid() || addr.IsUnspecified() {
			continue
		}
		return "http://" + net.JoinHostPort(addr.String(), strconv.Itoa(port)), true
	}
	return "", false
}

// Choose picks at most `r` peers at random.
//
// Random rather than fixed: a node that always asked the same peers would let
// those peers decide what the rest of the mesh hears, and in a network small
// enough to fit in a house "the same three" is often "all the ones an attacker
// owns". Fewer peers than `r` is everybody, which is the normal case for a
// homelab.
func Choose(peers []string, r int, source *rand.Rand) []string {
	if r <= 0 || len(peers) == 0 {
		return nil
	}
	order := source.Perm(len(peers))
	if r > len(order) {
		r = len(order)
	}
	out := make([]string, 0, r)
	for _, i := range order[:r] {
		out = append(out, peers[i])
	}
	return out
}
