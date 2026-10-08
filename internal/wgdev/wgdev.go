// Package wgdev drives a real WireGuard interface through wgctrl.
//
// It is the only package in Norn that talks to a kernel, and the only one that
// pulls the wgctrl dependency (D-059). Everything above it — the reconciler,
// the agent, every attack case — works against `peertable.Device` and is
// tested without a WireGuard interface at all.
//
// What lives here is therefore almost entirely **conversion**: Norn's types in,
// wgctrl's types out. That is deliberate, because conversion is exactly where a
// silent mistake becomes a security or availability bug — a nil endpoint that
// should have been "leave it alone", an allowed-ips list that replaces when it
// should add. The conversions are pure functions with their own tests, so the
// part that cannot be tested without a kernel is as small as it can be.
package wgdev

import (
	"fmt"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/onembyte/norn/internal/peertable"
)

// Device is a WireGuard interface.
type Device struct {
	client client
	name   string
}

// client keeps device reads testable without opening a kernel socket.
type client interface {
	Device(string) (*wgtypes.Device, error)
	ConfigureDevice(string, wgtypes.Config) error
	Close() error
}

// OwnKey implements peertable.Device.
func (d *Device) OwnKey() (peertable.Key, error) {
	device, err := d.client.Device(d.name)
	if err != nil {
		return peertable.Key{}, fmt.Errorf("wgdev: reading %s: %w", d.name, err)
	}
	return peertable.Key(device.PublicKey), nil
}

// Open connects to the interface by name.
func Open(name string) (*Device, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgdev: opening wgctrl: %w", err)
	}
	if _, err := client.Device(name); err != nil {
		client.Close()
		return nil, fmt.Errorf("wgdev: %s: %w", name, err)
	}
	return &Device{client: client, name: name}, nil
}

// Close releases the wgctrl client.
func (d *Device) Close() error { return d.client.Close() }

// Name is the interface this device drives.
func (d *Device) Name() string { return d.name }

// Peers implements peertable.Device.
func (d *Device) Peers() ([]peertable.Peer, error) {
	device, err := d.client.Device(d.name)
	if err != nil {
		return nil, fmt.Errorf("wgdev: reading %s: %w", d.name, err)
	}
	out := make([]peertable.Peer, 0, len(device.Peers))
	for _, peer := range device.Peers {
		out = append(out, fromWG(peer))
	}
	return peertable.Sorted(out), nil
}

// Replace implements peertable.Device: the table becomes exactly these peers.
func (d *Device) Replace(peers []peertable.Peer) error {
	configs := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, peer := range peers {
		configs = append(configs, toWG(peer, false))
	}
	return d.configure(wgtypes.Config{ReplacePeers: true, Peers: configs})
}

// Remove implements peertable.Device: these keys go, nothing else is touched.
func (d *Device) Remove(keys []peertable.Key) error {
	configs := make([]wgtypes.PeerConfig, 0, len(keys))
	for _, key := range keys {
		configs = append(configs, wgtypes.PeerConfig{
			PublicKey: wgtypes.Key(key), Remove: true,
		})
	}
	return d.configure(wgtypes.Config{Peers: configs})
}

// UpdateEndpoints implements peertable.Device: refresh reachability only, and
// never add a key that is absent.
func (d *Device) UpdateEndpoints(peers []peertable.Peer) error {
	configs := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, peer := range peers {
		configs = append(configs, toWG(peer, true))
	}
	return d.configure(wgtypes.Config{Peers: configs})
}

func (d *Device) configure(config wgtypes.Config) error {
	if err := d.client.ConfigureDevice(d.name, config); err != nil {
		return fmt.Errorf("wgdev: configuring %s: %w", d.name, err)
	}
	return nil
}

// toWG converts one peer into wgctrl's shape.
//
// These optional fields are pointers in wgctrl, and nil means "leave it as it
// is". That is exactly what Norn wants when a provider supplied nothing: a
// roaming peer's endpoint was learned from its handshakes and exists nowhere
// else, so writing a zero there would take the peer offline until it happened
// to handshake again.
func toWG(peer peertable.Peer, updateOnly bool) wgtypes.PeerConfig {
	config := wgtypes.PeerConfig{
		PublicKey:  wgtypes.Key(peer.Key),
		UpdateOnly: updateOnly,
		// Allowed-ips are authority, so they are set exactly rather than
		// added to: an entry Norn did not put there must not survive.
		ReplaceAllowedIPs: !updateOnly,
		AllowedIPs:        toIPNets(peer.AllowedIPs),
	}
	if peer.Endpoint.IsValid() {
		config.Endpoint = net.UDPAddrFromAddrPort(peer.Endpoint)
	}
	if peer.PresharedKey != ([peertable.KeyLen]byte{}) {
		preshared := wgtypes.Key(peer.PresharedKey)
		config.PresharedKey = &preshared
	}
	if peer.Keepalive > 0 {
		keepalive := peer.Keepalive
		config.PersistentKeepaliveInterval = &keepalive
	}
	if updateOnly {
		// A refresh must not rewrite routing.
		config.ReplaceAllowedIPs = false
		config.AllowedIPs = nil
	}
	return config
}

// fromWG converts what the kernel reports.
func fromWG(peer wgtypes.Peer) peertable.Peer {
	out := peertable.Peer{
		Key:          peertable.Key(peer.PublicKey),
		PresharedKey: [peertable.KeyLen]byte(peer.PresharedKey),
		AllowedIPs:   fromIPNets(peer.AllowedIPs),
		Keepalive:    peer.PersistentKeepaliveInterval,
	}
	if peer.Endpoint != nil {
		if addr, ok := netip.AddrFromSlice(peer.Endpoint.IP); ok {
			out.Endpoint = netip.AddrPortFrom(addr.Unmap(), uint16(peer.Endpoint.Port))
		}
	}
	return out
}

func toIPNets(prefixes []netip.Prefix) []net.IPNet {
	out := make([]net.IPNet, 0, len(prefixes))
	for _, prefix := range prefixes {
		bits := prefix.Addr().BitLen()
		out = append(out, net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), bits),
		})
	}
	return out
}

func fromIPNets(nets []net.IPNet) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(nets))
	for _, n := range nets {
		addr, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, _ := n.Mask.Size()
		out = append(out, netip.PrefixFrom(addr.Unmap(), ones))
	}
	return out
}

var _ peertable.Device = (*Device)(nil)
