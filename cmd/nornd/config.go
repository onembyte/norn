package main

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/onembyte/norn/internal/endpoint"
	"github.com/onembyte/norn/internal/reconcile"
)

// Config is `nornd.toml` (`ENFORCEMENT.md` part 5).
//
// Every field has a flag that overrides it, so a lab can run without a file
// and a deployment can keep everything in one.
type Config struct {
	Interface string `toml:"interface"`
	// Mode defaults to observe, and that default is load-bearing: a daemon
	// that enforced because a field was missing would take a network down on
	// a typo (D-005).
	Mode   string `toml:"mode"`
	Poll   string `toml:"poll"`
	Trust  string `toml:"trust"`
	Log    string `toml:"log"`
	RunDir string `toml:"run_dir"`
	Hints  string `toml:"hints_file"`
	Peers  []Peer `toml:"peer"`
}

// Peer is a `[[peer]]` block: reachability for one device the log proves.
//
// There is no key here, and there cannot be one. Keys come from the log; this
// file says where a proven device is expected to be found.
type Peer struct {
	DeviceID   string   `toml:"device_id"`
	AllowedIPs []string `toml:"allowed_ips"`
	Endpoint   string   `toml:"endpoint"`
	Keepalive  int      `toml:"keepalive"`
}

// LoadConfig reads a config file, refusing anything it does not understand.
//
// Unknown keys are an error rather than a shrug: a misspelled `mode` that
// silently left a node in observe would be a node quietly not enforcing, and
// a misspelled `device_id` would be a peer quietly unrouted.
func LoadConfig(path string) (Config, error) {
	var config Config
	meta, err := toml.DecodeFile(path, &config)
	if err != nil {
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return Config{}, fmt.Errorf("%s: unknown setting %q", path, undecoded[0].String())
	}
	return config, nil
}

// Static turns the `[[peer]]` blocks into an endpoint provider.
func (c Config) Static() (endpoint.Static, error) {
	peers := make(map[string]endpoint.Hints, len(c.Peers))
	for _, peer := range c.Peers {
		if peer.DeviceID == "" {
			return endpoint.Static{}, fmt.Errorf("a [[peer]] block has no device_id")
		}
		if _, repeated := peers[peer.DeviceID]; repeated {
			return endpoint.Static{}, fmt.Errorf("two [[peer]] blocks for %q", peer.DeviceID)
		}
		var hints endpoint.Hints
		for _, cidr := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return endpoint.Static{}, fmt.Errorf("%s: %q is not a CIDR", peer.DeviceID, cidr)
			}
			hints.AllowedIPs = append(hints.AllowedIPs, prefix)
		}
		if peer.Endpoint != "" {
			addr, err := netip.ParseAddrPort(peer.Endpoint)
			if err != nil {
				return endpoint.Static{}, fmt.Errorf("%s: %q is not host:port", peer.DeviceID, peer.Endpoint)
			}
			hints.Endpoint = addr
		}
		if peer.Keepalive < 0 {
			return endpoint.Static{}, fmt.Errorf("%s: a negative keepalive", peer.DeviceID)
		}
		hints.Keepalive = time.Duration(peer.Keepalive) * time.Second
		peers[peer.DeviceID] = hints
	}
	return endpoint.Static{Peers: peers}, nil
}

// ParseMode accepts only the three modes, because a fourth spelling of
// "enforce" must not quietly become observe.
func ParseMode(text string) (reconcile.Mode, error) {
	switch reconcile.Mode(text) {
	case "":
		return reconcile.Observe, nil // D-005
	case reconcile.Observe, reconcile.Owner, reconcile.Watchdog:
		return reconcile.Mode(text), nil
	default:
		return "", fmt.Errorf("%q is not a mode; use observe, owner or watchdog", text)
	}
}

// ParsePoll reads the polling interval.
//
// Linux has no peer-change events (`ENFORCEMENT.md` part 2), so watchdog and
// observe modes poll, and the interval is the eviction window. A zero would be
// a busy loop and a very long one would be a wide window, so both are refused.
func ParsePoll(text string) (time.Duration, error) {
	if text == "" {
		return DefaultPoll, nil
	}
	poll, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("poll: %w", err)
	}
	if poll < MinPoll || poll > MaxPoll {
		return 0, fmt.Errorf("poll must be between %s and %s, got %s", MinPoll, MaxPoll, poll)
	}
	return poll, nil
}

// Polling bounds. 200 ms is the interval `ENFORCEMENT.md` part 2 calls free:
// a netlink dump of a 1 000-peer interface is well under a millisecond.
const (
	DefaultPoll = 200 * time.Millisecond
	MinPoll     = 10 * time.Millisecond
	MaxPoll     = time.Hour
)
