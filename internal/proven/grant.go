package proven

import (
	"net/netip"
	"sort"
	"strings"
)

// Grant is a device's grant (§4.0, D-073): the prefixes its `ip` label
// carries, each masked to its prefix, duplicates removed, sorted as text --
// the bound on the allowed-ips a node will install for it (§13.1).
//
// Parsed as a whole: a label with one part that is not a prefix is no grant
// at all, not the parts that did parse, because a bound with a hole in it is
// not the bound the signers signed. An IPv4-mapped IPv6 prefix is no grant
// either: the two implementations' text forms of one differ, and a grant is
// compared as text. nil is no grant.
func Grant(labels map[string]string) []string {
	label, ok := labels[LabelIP]
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(label, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil || prefix.Addr().Is4In6() {
			return nil
		}
		text := prefix.Masked().String()
		if !seen[text] {
			seen[text] = true
			out = append(out, text)
		}
	}
	sort.Strings(out)
	return out
}

// LabelIP is the reserved label that carries the grant (§4.0).
const LabelIP = "ip"
