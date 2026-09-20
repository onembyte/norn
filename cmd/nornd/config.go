package main

import (
	"fmt"
	"github.com/onembyte/norn/internal/agent"
	"log/slog"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
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
	// HardStale is S_hard: the age past which this node drops every peer.
	// Absent means never, and that default is load-bearing -- it is the one
	// setting that lets Norn disconnect a node by itself.
	HardStale string `toml:"hard_stale"`
	// MaxSkew is Δclock. Absent means freshness.DefaultMaxSkew.
	MaxSkew string `toml:"max_skew"`
	Hints   string `toml:"hints_file"`
	Peers   []Peer `toml:"peer"`

	// FightPolicy is what to do when the same key keeps coming back:
	// "alarm" (the default) or "quarantine".
	FightPolicy    string `toml:"fight_policy"`
	FightThreshold int    `toml:"fight_threshold"`
	FightWindow    string `toml:"fight_window"`
	// QuarantineCommand takes the interface out of service. `{iface}` is
	// replaced with the interface name. It is a command rather than a library
	// call on purpose: taking a network down is a break-glass action, and an
	// operator should be able to read exactly what it will run -- and replace
	// it with `wg-quick down`, a firewall rule, or whatever their site uses.
	QuarantineCommand []string `toml:"quarantine_command"`
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

// ParseHardStale reads S_hard, the age past which the enforcer drops every
// peer (`GOSSIP.md` part 5).
//
// Empty or zero means never, because this is the one setting that lets Norn
// take a node off its own network: an operator has to ask for it in writing.
// A value below the §4.5 `staleness` default is refused -- it would drop every
// peer before the network had even called the view degraded, which is a typo
// with an outage attached rather than a configuration.
func ParseHardStale(text string) (time.Duration, error) {
	if text == "" {
		return 0, nil
	}
	hard, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("hard_stale: %w", err)
	}
	if hard == 0 {
		return 0, nil
	}
	if hard < MinHardStale {
		return 0, fmt.Errorf("hard_stale must be at least %s (the §4.5 staleness "+
			"default), or 0 to leave it off; got %s", MinHardStale, hard)
	}
	return hard, nil
}

// MinHardStale is SPEC §4.5's default `staleness`: below it, hard-stale would
// fire before degraded.
const MinHardStale = 600 * time.Second

// ParseMaxSkew reads Δclock. Empty means the freshness package's default.
func ParseMaxSkew(text string) (time.Duration, error) {
	if text == "" {
		return 0, nil
	}
	skew, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("max_skew: %w", err)
	}
	if skew <= 0 {
		return 0, fmt.Errorf("max_skew must be positive, got %s", skew)
	}
	return skew, nil
}

// Polling bounds. 200 ms is the interval `ENFORCEMENT.md` part 2 calls free:
// a netlink dump of a 1 000-peer interface is well under a millisecond.
const (
	DefaultPoll = 200 * time.Millisecond
	MinPoll     = 10 * time.Millisecond
	MaxPoll     = time.Hour
)

// FightSettings resolves the fight policy and its knobs.
func (c Config) FightSettings() (policy string, threshold int, window time.Duration, err error) {
	policy = c.FightPolicy
	switch policy {
	case "":
		policy = agent.PolicyAlarm
	case agent.PolicyAlarm, agent.PolicyQuarantine:
	default:
		return "", 0, 0, fmt.Errorf("fight_policy %q is not a policy; use %q or %q",
			policy, agent.PolicyAlarm, agent.PolicyQuarantine)
	}
	if c.FightThreshold < 0 {
		return "", 0, 0, fmt.Errorf("fight_threshold cannot be negative")
	}
	if c.FightWindow != "" {
		window, err = time.ParseDuration(c.FightWindow)
		if err != nil {
			return "", 0, 0, fmt.Errorf("fight_window: %w", err)
		}
		if window <= 0 {
			return "", 0, 0, fmt.Errorf("fight_window must be positive")
		}
	}
	return policy, c.FightThreshold, window, nil
}

// QuarantineFor builds the action the quarantine policy runs, or explains why
// it cannot.
func (c Config) QuarantineFor(iface string, logger *slog.Logger) (func(string) error, error) {
	command := c.QuarantineCommand
	if len(command) == 0 {
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("quarantine needs a quarantine_command on %s: there is "+
				"no command here that Norn can assume takes an interface down", runtime.GOOS)
		}
		command = []string{"ip", "link", "set", "{iface}", "down"}
	}
	resolved := make([]string, len(command))
	for i, part := range command {
		resolved[i] = strings.ReplaceAll(part, "{iface}", iface)
	}
	return func(reason string) error {
		logger.Warn("quarantining the interface", "reason", reason, "command", resolved)
		out, err := exec.Command(resolved[0], resolved[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(resolved, " "), err,
				strings.TrimSpace(string(out)))
		}
		return nil
	}, nil
}
