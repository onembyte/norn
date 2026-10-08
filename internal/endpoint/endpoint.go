// Package endpoint supplies the parts of a peer that are not keys.
//
// `ENFORCEMENT.md` part 5: keys come from the log, and endpoints, allowed-ips
// and keepalives come from a provider which is **deliberately untrusted for
// keys**. A control plane that tries to add a peer is thereby demoted to an
// endpoint directory — the role it should have had.
//
// That is enforced by the shape rather than by a check: Hints has no key
// field, so there is no way for a provider to name a peer at all. It answers
// questions about devices the log has already proven, and the set of devices
// it may speak about is not its to choose.
package endpoint

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/peertable"
)

// Hints are the reachability details for one proven device. There is no key
// here, and that absence is the security property.
type Hints struct {
	AllowedIPs []netip.Prefix
	Endpoint   netip.AddrPort
	Keepalive  time.Duration
}

// Provider answers for devices the log has proven.
type Provider interface {
	// Name identifies the provider in logs and alarms.
	Name() string
	// Hints returns what is known about this device.
	Hints(device Device) (Hints, bool)
	// Knows lists the device ids this provider has opinions about, so that
	// opinions about devices the log does not prove can be reported rather
	// than silently ignored.
	Knows() []string
}

// Device is a proven device, as the verifier hands it over: an identity, a key
// the log proves, and whatever labels a signer attached.
type Device struct {
	ID     string
	Key    peertable.Key
	Labels map[string]string
	// Grant is the §4.0 grant: the prefixes the signers authorised this
	// device to source, masked. nil is no grant, which under
	// `params.routes = "granted"` means a key and no routes (D-073).
	Grant []netip.Prefix
}

// Report is what a provider had to say that could not be used.
type Report struct {
	// Unproven are device ids the provider knows about and the log does not
	// prove. A control plane's keys land here, which is the point.
	Unproven []string
	// Unrouted are proven devices no provider could place. They are still
	// installed -- dropping a proven device because nobody configured it
	// would be enforcement removing a peer the log vouches for.
	Unrouted []string
	// Malformed are hints that did not parse, by device and field.
	Malformed []string
	// Overlapping are pairs of proven devices whose allowed-ips overlap, as
	// "a 10.9.0.0/24 overlaps b 10.9.0.2/32". Neither device is given the
	// overlapping prefix: WireGuard routes a packet to the peer with the most
	// specific matching prefix, so an overlap silently hands one device's
	// addresses to another, and nothing in the log decided that (SEC-035).
	Overlapping []string
	// Widened are prefixes a provider gave a device outside that device's
	// grant, as "router 0.0.0.0/0", withheld under `routes = "granted"`: a
	// provider may narrow a grant and never widen it (D-073).
	Widened []string
	// Ungranted are proven devices with no grant, installed with their key
	// and no allowed-ips under `routes = "granted"`.
	Ungranted []string
}

// Empty reports whether everything a provider said was usable.
func (r Report) Empty() bool {
	return len(r.Unproven) == 0 && len(r.Unrouted) == 0 && len(r.Malformed) == 0 &&
		len(r.Overlapping) == 0 && len(r.Widened) == 0 && len(r.Ungranted) == 0
}

// DesiredGranted is Desired under `params.routes = "granted"` (§13.1, D-073):
// a provider's prefix is kept only where it lies within the device's grant,
// and a device with no grant is installed with its key and no allowed-ips.
// In WireGuard a peer's allowed-ips is its authority to source those
// addresses, so a provider may narrow a grant and never widen it; what it
// tried to widen is reported, as an overlap is.
func DesiredGranted(proven []Device, provider Provider) ([]peertable.Peer, Report) {
	return desired(proven, provider, true)
}

// withinGrant reports whether every address of prefix lies inside one of
// the grant's prefixes. Both sides are masked, so containment is a prefix
// at least as long as a grant prefix whose network holds its first address.
func withinGrant(prefix netip.Prefix, grant []netip.Prefix) bool {
	for _, g := range grant {
		if g.Addr().Is4() == prefix.Addr().Is4() && g.Bits() <= prefix.Bits() && g.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

// Desired builds the peer table the proven set implies, with the provider's
// prefixes as given: `params.routes = "advisory"` (D-026's reading).
//
// Every peer here comes from a proven device; the provider only decorates it.
// A provider that mentions a device the log does not prove cannot add a peer
// by doing so — it is reported and dropped.
func Desired(proven []Device, provider Provider) ([]peertable.Peer, Report) {
	return desired(proven, provider, false)
}

func desired(proven []Device, provider Provider, granted bool) ([]peertable.Peer, Report) {
	var report Report
	byID := make(map[string]bool, len(proven))
	for _, device := range proven {
		byID[device.ID] = true
	}
	for _, id := range provider.Knows() {
		if !byID[id] {
			report.Unproven = append(report.Unproven, id)
		}
	}
	sort.Strings(report.Unproven)

	peers := make([]peertable.Peer, 0, len(proven))
	for _, device := range proven {
		peer := peertable.Peer{Key: device.Key}
		if hints, ok := provider.Hints(device); ok {
			// Every provider meets here, including ones returning prefixes
			// directly. Match the kernel's route form before reconciliation,
			// without changing the provider's own hints.
			for _, prefix := range hints.AllowedIPs {
				peer.AllowedIPs = append(peer.AllowedIPs, prefix.Masked())
			}
			peer.Endpoint = hints.Endpoint
			peer.Keepalive = hints.Keepalive
		}
		if granted {
			if proven[len(peers)].Grant == nil {
				peer.AllowedIPs = nil
				report.Ungranted = append(report.Ungranted, device.ID)
			} else {
				var kept []netip.Prefix
				for _, prefix := range peer.AllowedIPs {
					if withinGrant(prefix, device.Grant) {
						kept = append(kept, prefix)
					} else {
						report.Widened = append(report.Widened, device.ID+" "+prefix.String())
					}
				}
				peer.AllowedIPs = kept
			}
		}
		peers = append(peers, peer)
	}
	// Overlaps are judged on what would be installed, after the bound.
	report.Overlapping = withholdOverlaps(proven, peers)
	ungranted := make(map[string]bool, len(report.Ungranted))
	for _, id := range report.Ungranted {
		ungranted[id] = true
	}
	for i, peer := range peers {
		// A device with no grant has no routes because the log gave it none,
		// not because no provider placed it: that is Ungranted, said once.
		if len(peer.AllowedIPs) == 0 && !ungranted[proven[i].ID] {
			report.Unrouted = append(report.Unrouted, proven[i].ID)
		}
	}
	return peertable.Sorted(peers), report
}

// withholdOverlaps removes from every peer each prefix that overlaps a prefix
// of another peer, and says which pairs did. Both sides lose the prefix: the
// provider gave two devices the same addresses, and choosing one would be
// Norn deciding something nobody signed. A device's other prefixes are its
// own and stay. peers[i] belongs to proven[i].
func withholdOverlaps(proven []Device, peers []peertable.Peer) []string {
	var found []string
	withheld := make([]map[netip.Prefix]bool, len(peers))
	for i := range peers {
		withheld[i] = map[netip.Prefix]bool{}
	}
	for i := range peers {
		for j := i + 1; j < len(peers); j++ {
			for _, a := range peers[i].AllowedIPs {
				for _, b := range peers[j].AllowedIPs {
					if !a.Overlaps(b) {
						continue
					}
					withheld[i][a], withheld[j][b] = true, true
					first, second := proven[i].ID+" "+a.String(), proven[j].ID+" "+b.String()
					if second < first {
						first, second = second, first
					}
					found = append(found, first+" overlaps "+second)
				}
			}
		}
	}
	for i := range peers {
		if len(withheld[i]) == 0 {
			continue
		}
		var kept []netip.Prefix
		for _, prefix := range peers[i].AllowedIPs {
			if !withheld[i][prefix] {
				kept = append(kept, prefix)
			}
		}
		peers[i].AllowedIPs = kept
	}
	sort.Strings(found)
	return found
}

// Static answers from a table an operator wrote, keyed by device id.
//
// The homelab default: a `wg-quick` file with only `[Interface]`, plus Norn,
// is a complete setup.
type Static struct {
	Peers map[string]Hints
}

// Name implements Provider.
func (s Static) Name() string { return "static" }

// Hints implements Provider.
func (s Static) Hints(device Device) (Hints, bool) {
	hints, ok := s.Peers[device.ID]
	return hints, ok
}

// Knows implements Provider.
func (s Static) Knows() []string {
	out := make([]string, 0, len(s.Peers))
	for id := range s.Peers {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Labels answers from the labels on the device's own `enroll` entry.
//
// Those labels are signed by a signer, which makes them authenticated but not
// authoritative: they say where a device is expected to be, not who it is. A
// label that does not parse is reported and ignored rather than failing the
// device — a typo in an endpoint should not evict a peer the log proves.
type Labels struct {
	// Malformed collects parse failures for the caller to report.
	Malformed []string
}

// Label keys read by this provider.
const (
	LabelIP        = "ip"
	LabelEndpoint  = "endpoint"
	LabelKeepalive = "keepalive"
)

// Name implements Provider.
func (l *Labels) Name() string { return "labels" }

// Knows implements Provider: labels travel with the device, so this provider
// never speaks about a device the log has not proven.
func (l *Labels) Knows() []string { return nil }

// Hints implements Provider.
func (l *Labels) Hints(device Device) (Hints, bool) {
	var hints Hints
	var found bool

	if text, ok := device.Labels[LabelIP]; ok {
		prefixes, err := ParsePrefixes(text)
		if err != nil {
			l.Malformed = append(l.Malformed, fmt.Sprintf("%s.%s: %v", device.ID, LabelIP, err))
		} else {
			hints.AllowedIPs, found = prefixes, true
		}
	}
	if text, ok := device.Labels[LabelEndpoint]; ok {
		addr, err := netip.ParseAddrPort(strings.TrimSpace(text))
		if err != nil {
			l.Malformed = append(l.Malformed, fmt.Sprintf("%s.%s: %v", device.ID, LabelEndpoint, err))
		} else {
			hints.Endpoint, found = addr, true
		}
	}
	if text, ok := device.Labels[LabelKeepalive]; ok {
		seconds, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil || seconds < 0 {
			l.Malformed = append(l.Malformed, fmt.Sprintf("%s.%s: not a number of seconds", device.ID, LabelKeepalive))
		} else {
			hints.Keepalive, found = time.Duration(seconds)*time.Second, true
		}
	}
	return hints, found
}

// ParsePrefixes reads a comma-separated list of CIDRs, as WireGuard writes
// allowed-ips.
func ParsePrefixes(text string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, field := range strings.Split(text, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR", field)
		}
		out = append(out, prefix)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no routes")
	}
	return out, nil
}

// First asks each provider in turn and takes the first answer, so an operator
// can pin one device in `nornd.toml` and let the rest follow their labels.
type First []Provider

// Name implements Provider.
func (f First) Name() string {
	names := make([]string, 0, len(f))
	for _, provider := range f {
		names = append(names, provider.Name())
	}
	return strings.Join(names, "+")
}

// Hints implements Provider.
func (f First) Hints(device Device) (Hints, bool) {
	for _, provider := range f {
		if hints, ok := provider.Hints(device); ok {
			return hints, true
		}
	}
	return Hints{}, false
}

// Knows implements Provider.
func (f First) Knows() []string {
	seen := map[string]bool{}
	var out []string
	for _, provider := range f {
		for _, id := range provider.Knows() {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}

// None is a provider that knows nothing: every proven device is installed with
// no routes, and reported as unrouted.
type None struct{}

// Name implements Provider.
func (None) Name() string { return "none" }

// Hints implements Provider.
func (None) Hints(Device) (Hints, bool) { return Hints{}, false }

// Knows implements Provider.
func (None) Knows() []string { return nil }
