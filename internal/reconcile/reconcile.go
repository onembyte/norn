// Package reconcile decides what to do about the difference between the peers
// an interface has and the peers the log proves.
//
// Every decision here is a pure function of (mode, actual, desired). That is
// deliberate: the behaviour worth testing is what happens **while somebody
// else is writing to the table**, and against a kernel those cases are slow,
// racy and hard to arrange. As functions they are ordinary tests — including
// `ENFORCEMENT.md`'s A1 swap attack, which is a paragraph in the design and a
// test case here.
//
// The split also keeps the dangerous part small: Apply does the writes and
// makes no decisions, Decide makes the decisions and touches nothing.
package reconcile

import (
	"fmt"
	"net/netip"

	"github.com/onembyte/norn/internal/peertable"
)

// Mode is who owns the peer table (`ENFORCEMENT.md` part 3).
type Mode string

const (
	// Observe reads and never writes. The mandatory first mode everywhere (D-005).
	Observe Mode = "observe"
	// Owner makes Norn the sole writer: the table is the proven set.
	Owner Mode = "owner"
	// Watchdog leaves the table to somebody else and evicts what is not proven.
	Watchdog Mode = "watchdog"
)

// Alarm kinds, as `ENFORCEMENT.md` part 3 names them.
const (
	// UnprovenPeer: a key in the table that the log does not prove.
	UnprovenPeer = "UNPROVEN_PEER"
	// MissingPeer: a proven device the table does not carry. Informational —
	// in watchdog mode the control plane may simply not have connected it yet,
	// and installing it is not Norn's job (G4 non-goal).
	MissingPeer = "MISSING_PEER"
	// EvictedPeer: an unproven key Norn removed.
	EvictedPeer = "EVICTED_PEER"
)

// Alarm is something an operator needs to know about.
//
// It carries what the key was given, not just the key: a stray peer with a
// /32 and a routing hijack with 0.0.0.0/0 are the same event otherwise, and
// they are not the same event.
type Alarm struct {
	Kind       string
	Key        peertable.Key
	AllowedIPs []netip.Prefix
	Endpoint   netip.AddrPort
	DeviceID   string // when the key is one the log proves
}

// Plan is what a reconciliation decided to do.
type Plan struct {
	// Replace, when non-nil, is the whole table to write (owner mode).
	Replace []peertable.Peer
	// Remove are keys to evict, touching nothing else (watchdog mode).
	Remove []peertable.Key
	// Update refreshes reachability for keys already present (UpdateOnly).
	Update []peertable.Peer
	Alarms []Alarm
	// Invalid marks a mode this package does not know. Doing nothing quietly
	// would look exactly like a healthy observe run.
	Invalid bool
}

// WritesAnything reports whether the plan touches the interface at all, which
// is the question observe mode has to answer "no" to forever.
func (p Plan) WritesAnything() bool {
	return p.Replace != nil || len(p.Remove) > 0 || len(p.Update) > 0
}

// Decide works out what to do. It performs no I/O and mutates nothing.
//
// `desired` is the proven set already dressed with whatever an endpoint
// provider supplied (part 5); this package does not care where that came from,
// only that keys in it are proven.
func Decide(mode Mode, actual, desired []peertable.Peer) Plan {
	have, want := peertable.ByKey(actual), peertable.ByKey(desired)

	var plan Plan
	for _, peer := range peertable.Sorted(actual) {
		if _, proven := want[peer.Key]; !proven {
			plan.Alarms = append(plan.Alarms, alarmFor(UnprovenPeer, peer))
		}
	}
	for _, peer := range peertable.Sorted(desired) {
		if _, present := have[peer.Key]; !present {
			plan.Alarms = append(plan.Alarms, alarmFor(MissingPeer, peer))
		}
	}

	switch mode {
	case Observe:
		return plan

	case Owner:
		// The table Norn wants, keeping any endpoint the interface has
		// learned where the provider supplied none.
		target := make([]peertable.Peer, 0, len(desired))
		for _, peer := range peertable.Sorted(desired) {
			// The log says nothing about preshared keys, so enforcement
			// preserves the operator's choice for every peer it keeps.
			peer.PresharedKey = have[peer.Key].PresharedKey
			target = append(target, withLearnedEndpoint(peer, have[peer.Key]))
		}
		if routingDiffers(have, want) {
			plan.Replace = target
			return plan
		}
		for _, peer := range target {
			if current, present := have[peer.Key]; present && !current.SameEndpoint(peer) {
				plan.Update = append(plan.Update, peer)
			}
		}
		return plan

	case Watchdog:
		// Evict what is not proven, and install nothing: whoever owns this
		// table owns its availability too.
		for _, peer := range peertable.Sorted(actual) {
			if _, proven := want[peer.Key]; !proven {
				plan.Remove = append(plan.Remove, peer.Key)
				plan.Alarms = append(plan.Alarms, alarmFor(EvictedPeer, peer))
			}
		}
		return plan

	default:
		return Plan{Invalid: true}
	}
}

// routingDiffers reports whether the set of keys, or any key's allowed-ips,
// is not what the log proves. Endpoints are excluded: they are refreshed, not
// grounds for rewriting the table.
func routingDiffers(have, want map[peertable.Key]peertable.Peer) bool {
	if len(have) != len(want) {
		return true
	}
	for key, wanted := range want {
		current, present := have[key]
		if !present || !current.SameRouting(wanted) {
			return true
		}
	}
	return false
}

// withLearnedEndpoint keeps what the interface knows when the provider does
// not know better.
//
// WireGuard learns a peer's endpoint from its handshakes, and a roaming peer's
// endpoint exists nowhere else. Rewriting the table with a zero endpoint would
// discard it and take the peer offline until it happens to handshake again --
// an outage caused by enforcement, on a peer that was never in question.
func withLearnedEndpoint(wanted, current peertable.Peer) peertable.Peer {
	if wanted.Endpoint.IsValid() {
		return wanted
	}
	wanted.Endpoint = current.Endpoint
	return wanted
}

func alarmFor(kind string, peer peertable.Peer) Alarm {
	return Alarm{Kind: kind, Key: peer.Key, AllowedIPs: peer.AllowedIPs,
		Endpoint: peer.Endpoint}
}

// Apply performs a plan. It decides nothing.
func Apply(device peertable.Device, plan Plan) error {
	if plan.Invalid {
		return fmt.Errorf("reconcile: refusing to act on an invalid plan")
	}
	if plan.Replace != nil {
		if err := device.Replace(plan.Replace); err != nil {
			return fmt.Errorf("reconcile: rewriting the peer table: %w", err)
		}
	}
	if len(plan.Remove) > 0 {
		if err := device.Remove(plan.Remove); err != nil {
			return fmt.Errorf("reconcile: evicting %d peer(s): %w", len(plan.Remove), err)
		}
	}
	if len(plan.Update) > 0 {
		if err := device.UpdateEndpoints(plan.Update); err != nil {
			return fmt.Errorf("reconcile: refreshing endpoints: %w", err)
		}
	}
	return nil
}
