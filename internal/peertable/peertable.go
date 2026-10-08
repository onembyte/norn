// Package peertable is the seam between Norn and a WireGuard interface.
//
// `ENFORCEMENT.md` part 1: WireGuard decides whom to talk to in exactly one
// place — the interface's cryptokey routing table of (public key, allowed-ips,
// endpoint) — and Norn enforces there and nowhere else. This package is the
// whole of what Norn is allowed to touch.
//
// It is deliberately narrow in two directions. It exposes no private key, no
// listen port and no fwmark, because `nornd` never writes those and an
// interface it cannot express cannot be broken by accident. And it names no
// implementation: the reconciler decides against this interface, so every
// decision — including the ones that only happen when an attacker is present —
// is a unit test rather than a lab run.
package peertable

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// KeyLen is the length of a WireGuard public key.
const KeyLen = 32

// Key is a WireGuard public key. It is a value type so that peers can be
// compared and used as map keys without anybody reaching for a slice.
type Key [KeyLen]byte

// ParseKey reads WireGuard's own encoding: standard base64 of 32 bytes.
func ParseKey(text string) (Key, error) {
	var key Key
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return key, fmt.Errorf("peertable: not base64: %w", err)
	}
	if len(raw) != KeyLen {
		return key, fmt.Errorf("peertable: key is %d bytes, want %d", len(raw), KeyLen)
	}
	copy(key[:], raw)
	return key, nil
}

// KeyFromBytes converts a key already in hand, as the log stores it.
func KeyFromBytes(raw []byte) (Key, error) {
	var key Key
	if len(raw) != KeyLen {
		return key, fmt.Errorf("peertable: key is %d bytes, want %d", len(raw), KeyLen)
	}
	copy(key[:], raw)
	return key, nil
}

// String is WireGuard's encoding, so a key printed here can be pasted into
// `wg` or compared against `wg show` without translation.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Short is the first characters of the key, for logs and alarms where the
// whole thing is noise but telling two keys apart still matters.
func (k Key) Short() string { return k.String()[:8] + "…" }

// Peer is one row of the cryptokey routing table.
type Peer struct {
	Key Key
	// PresharedKey is operator-managed; zero means none.
	PresharedKey [KeyLen]byte
	AllowedIPs   []netip.Prefix
	Endpoint     netip.AddrPort // zero when unknown; an endpoint is optional
	Keepalive    time.Duration  // zero means none
}

// SameRouting reports whether two peers would route identically.
//
// Endpoint and keepalive are excluded on purpose: they are the parts an
// endpoint provider supplies and may legitimately change (§5), while the key
// and its allowed-ips are what decide *who may send what*. Conflating them
// would make a roaming peer look like a security event.
func (p Peer) SameRouting(other Peer) bool {
	if p.Key != other.Key || len(p.AllowedIPs) != len(other.AllowedIPs) {
		return false
	}
	mine, theirs := sortedPrefixes(p.AllowedIPs), sortedPrefixes(other.AllowedIPs)
	for i := range mine {
		if mine[i] != theirs[i] {
			return false
		}
	}
	return true
}

// SameEndpoint reports whether the reachability details match.
func (p Peer) SameEndpoint(other Peer) bool {
	return p.Endpoint == other.Endpoint && p.Keepalive == other.Keepalive
}

func sortedPrefixes(in []netip.Prefix) []netip.Prefix {
	out := append([]netip.Prefix(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// ByKey indexes peers, which is how every comparison in the reconciler starts.
func ByKey(peers []Peer) map[Key]Peer {
	out := make(map[Key]Peer, len(peers))
	for _, peer := range peers {
		out[peer.Key] = peer
	}
	return out
}

// Sorted returns peers in a stable order, so that what a test compares and
// what an operator reads do not depend on map iteration.
func Sorted(peers []Peer) []Peer {
	out := append([]Peer(nil), peers...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key.String() < out[j].Key.String() })
	return out
}

// Device is the part of a WireGuard interface Norn drives.
//
// The three writes are exactly the three `ENFORCEMENT.md` part 2 names:
// ReplacePeers for owner mode, Remove for watchdog evictions, and UpdateOnly
// for refreshing endpoints without adding keys.
type Device interface {
	// OwnKey reads the interface's own public key. Zero with no error means
	// the interface has not been configured with a key yet.
	OwnKey() (Key, error)
	// Peers reads the current table.
	Peers() ([]Peer, error)
	// Replace makes the table exactly these peers (ReplacePeers: true).
	Replace(peers []Peer) error
	// Remove deletes these keys and touches nothing else.
	Remove(keys []Key) error
	// UpdateEndpoints refreshes reachability for keys already present, and
	// must not add a key that is absent (UpdateOnly).
	UpdateEndpoints(peers []Peer) error
}
