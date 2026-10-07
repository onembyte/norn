// Command nornd keeps a WireGuard interface in agreement with what the log
// proves.
//
// It runs in one of three modes (`ENFORCEMENT.md` part 3) and **observe is the
// default**: reads only, alarms on anything it does not recognise, writes
// nothing. Enforcing is something an operator turns on deliberately, on a node
// they have already watched behave (D-005).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/onembyte/norn/internal/agent"
	"github.com/onembyte/norn/internal/endpoint"
	"github.com/onembyte/norn/internal/freshness"
	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/trust"
	"github.com/onembyte/norn/internal/wgdev"
)

// DefaultRunDir is where the proven set is published (`ENFORCEMENT.md` part 9).
const DefaultRunDir = "/run/norn"

// DefaultStateDir is where what must outlive a reboot is kept (SEC-006): the
// FHS's place for state a program keeps between runs, which `/run` is not.
const DefaultStateDir = "/var/lib/norn"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nornd:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("nornd", flag.ContinueOnError)
	configPath := fs.String("config", "", "a nornd.toml to read settings from")
	iface := fs.String("iface", "", "the WireGuard interface to watch")
	mode := fs.String("mode", "", "observe (default), owner or watchdog")
	trustPath := fs.String("trust", "", "path to norn.trust")
	logLocation := fs.String("log", "", "log URL or directory; defaults to the anchor's log_urls")
	runDir := fs.String("run-dir", "", "where to publish proven.json (default "+DefaultRunDir+")")
	stateDir := fs.String("state-dir", "",
		"where the mirror and fork evidence outlive a reboot (default "+DefaultStateDir+")")
	poll := fs.String("poll", "", "how often to reconcile (default "+DefaultPoll.String()+")")
	hardStale := fs.String("hard-stale", "",
		"age past which every peer is dropped, e.g. 6h; off unless set")
	maxSkew := fs.String("max-skew", "",
		"how far this machine's clock may be from witness time before CLOCK_SKEW")
	gossipPort := fs.Int("gossip-port", DefaultGossipPort,
		"port for the peer gossip server, on the tunnel address only; 0 turns it off")
	once := fs.Bool("once", false, "run one cycle and exit")
	asJSON := fs.Bool("json", false, "log as JSON instead of text")
	if err := fs.Parse(args); err != nil {
		return err
	}

	config := Config{}
	if *configPath != "" {
		loaded, err := LoadConfig(*configPath)
		if err != nil {
			return err
		}
		config = loaded
	}
	// Flags win, so a running node can be overridden without editing a file.
	config.Interface = pick(*iface, config.Interface)
	config.Mode = pick(*mode, config.Mode)
	config.Trust = pick(*trustPath, config.Trust)
	config.Log = pick(*logLocation, config.Log)
	config.RunDir = pick(*runDir, config.RunDir, DefaultRunDir)
	config.StateDir = pick(*stateDir, config.StateDir, DefaultStateDir)
	config.Poll = pick(*poll, config.Poll)
	config.HardStale = pick(*hardStale, config.HardStale)
	config.SetGossipPort(*gossipPort, *gossipPort != DefaultGossipPort)
	config.MaxSkew = pick(*maxSkew, config.MaxSkew)

	logger := newLogger(*asJSON)
	cycle, interval, err := build(config, logger)
	if err != nil {
		return err
	}

	if *once {
		return cycle.Once()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return loop(ctx, cycle, interval, logger)
}

// build turns settings into a running agent, refusing anything unusable before
// the first cycle rather than during it.
func build(config Config, logger *slog.Logger) (*agent.Agent, time.Duration, error) {
	if config.Interface == "" {
		return nil, 0, errors.New("-iface is required: nornd watches one WireGuard interface")
	}
	if config.Trust == "" {
		return nil, 0, errors.New("-trust is required: a node without an anchor proves nothing")
	}
	mode, err := ParseMode(config.Mode)
	if err != nil {
		return nil, 0, err
	}
	hard, err := ParseHardStale(config.HardStale)
	if err != nil {
		return nil, 0, err
	}
	maxSkew, err := ParseMaxSkew(config.MaxSkew)
	if err != nil {
		return nil, 0, err
	}
	interval, err := ParsePoll(config.Poll)
	if err != nil {
		return nil, 0, err
	}

	// Say what this node is about to be before anything can fail. An operator
	// reading a startup error should be able to see which mode was intended,
	// because "it did not start" and "it started enforcing" are very
	// different things to be wrong about.
	fightPolicy, _, _, err := config.FightSettings()
	if err != nil {
		return nil, 0, err
	}
	logger.Info("nornd configuration",
		"interface", config.Interface, "mode", mode, "poll", interval,
		"trust", config.Trust, "run_dir", config.RunDir, "state_dir", config.StateDir,
		"fight_policy", fightPolicy)
	if fightPolicy == agent.PolicyQuarantine {
		logger.Warn("fight policy is quarantine: a control-plane fight will take this " +
			"interface out of service until an operator intervenes")
	}
	if mode == reconcile.Observe {
		logger.Info("observe mode: this node will alarm and write nothing (D-005)")
	}
	for _, warning := range stateDirWarnings(config.StateDir) {
		logger.Warn(warning)
	}

	raw, err := os.ReadFile(config.Trust)
	if err != nil {
		return nil, 0, fmt.Errorf("reading the trust file: %w", err)
	}
	anchor, err := trust.Parse(raw)
	if err != nil {
		return nil, 0, err
	}

	location := config.Log
	if location == "" {
		if len(anchor.LogURLs) == 0 {
			return nil, 0, errors.New("the anchor lists no log_urls; pass -log")
		}
		location = anchor.LogURLs[0]
	}
	fetcher, err := logclient.Open(location)
	if err != nil {
		return nil, 0, err
	}

	device, err := openDevice(config.Interface)
	if err != nil {
		return nil, 0, err
	}

	provider, err := providerFor(config)
	if err != nil {
		return nil, 0, err
	}

	policy, threshold, window, err := config.FightSettings()
	if err != nil {
		return nil, 0, err
	}
	var quarantine func(string) error
	if policy == agent.PolicyQuarantine {
		if quarantine, err = config.QuarantineFor(config.Interface, logger); err != nil {
			return nil, 0, err
		}
	}

	// A node asks its proven peers on T_g and when the log cannot be used,
	// at the same port it serves them on. The closure is filled in after the agent exists
	// because the peers it may ask are the ones the agent itself has proven --
	// there is no separate list to keep in step, and an unproven peer can
	// never end up on it.
	var cycle *agent.Agent
	gossipPort := config.GossipPortOrDefault()
	cycle, err = agent.New(agent.Config{
		Anchor: anchor, Fetcher: fetcher, Device: device, Provider: provider,
		Mode: mode, RunDir: config.RunDir, StateDir: config.StateDir, Now: time.Now,
		Hard: hard, MaxSkew: maxSkew,
		Peers:       func() []string { return cycle.PeerAddresses(gossipPort) },
		FightPolicy: policy, FightThreshold: threshold, FightWindow: window,
		Quarantine: quarantine,
		Emit:       func(event agent.Event) { report(logger, event) },
	})
	if err != nil {
		return nil, 0, err
	}

	// Serve this node's mirror to its peers, on the tunnel and nowhere else.
	// A failure here is reported and does not stop the node: gossip is how a
	// network survives a log outage, not how a node enforces, and refusing to
	// start because peers cannot reach us would trade the second for the
	// first.
	if gossipPort > 0 {
		addr, err := gossip.TunnelAddress(config.Interface, gossipPort)
		if err != nil {
			logger.Warn("not gossiping", "reason", err)
		} else {
			mirrorDir, evidenceDir := gossipDirs(config)
			serveGossip(logger, addr, mirrorDir, evidenceDir)
		}
	}

	logger.Info("nornd started", "network", anchor.Name, "origin", anchor.Origin,
		"log", location, "endpoints", provider.Name())
	return cycle, interval, nil
}

// openDevice is the kernel interface behind the agent's seam. A variable so a
// test can run a whole cycle of this binary's wiring without a WireGuard
// interface; nothing else replaces it.
var openDevice = func(name string) (peertable.Device, error) { return wgdev.Open(name) }

// gossipDirs is what this node serves its peers: the mirror it verified and
// the evidence of any fork it proved, from wherever the agent keeps them.
func gossipDirs(config Config) (mirror, evidence string) {
	return filepath.Join(config.StateDir, proven.MirrorDir),
		filepath.Join(config.StateDir, agent.ForkDir)
}

// providerFor assembles the endpoint providers in precedence order: what the
// operator pinned, then what another daemon wrote, then what the log's own
// labels suggest.
func providerFor(config Config) (endpoint.Provider, error) {
	static, err := config.Static()
	if err != nil {
		return nil, err
	}
	providers := endpoint.First{static}
	if config.Hints != "" {
		fromFile, err := endpoint.LoadFile(config.Hints)
		if err != nil {
			return nil, err
		}
		providers = append(providers, fromFile)
	}
	return append(providers, &endpoint.Labels{}), nil
}

// loop reconciles until the context is cancelled.
//
// A cycle that fails is logged and the loop continues. A daemon that exited on
// a log outage would stop evicting intruders at exactly the moment somebody
// might be counting on it to — the agent has already made sure a failure does
// not disturb the peer table.
func loop(ctx context.Context, cycle *agent.Agent, interval time.Duration, logger *slog.Logger) error {
	cycles, failures := 0, 0
	for {
		if err := cycle.Once(); err != nil {
			failures++
			logger.Warn("cycle failed; the peer table is unchanged", "error", err)
		}
		cycles++

		wait := nextPoll(interval, cycle.Freshness())
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			logger.Info("nornd stopping", "cycles", cycles, "failed", failures)
			return nil
		case <-timer.C:
		}
	}
}

// DegradedPoll is `GOSSIP.md` part 5's "poll all sources every 10 s" while
// degraded.
const DegradedPoll = 10 * time.Second

// nextPoll is how long to wait before the next cycle.
//
// A stale node tries harder, but only ever *harder*: a node already polling
// every 200 ms is not slowed down to ten seconds because its view went stale.
// The rule exists for a node configured to poll slowly -- which is a
// reasonable thing to do on a laptop, right up until the log goes quiet and
// nobody notices for five minutes.
func nextPoll(interval time.Duration, state string) time.Duration {
	if state != freshness.Degraded && state != freshness.HardStale {
		return interval
	}
	if interval < DegradedPoll {
		return interval
	}
	return DegradedPoll
}

// Every kind has a deliberate level, so outages and evidence of a fork cannot
// disappear among routine messages. The declaration test keeps this table in
// step with the agent and reconciler as they gain new kinds.
var eventLevels = map[string]slog.Level{
	agent.Fork:                  slog.LevelError,
	agent.Frozen:                slog.LevelError,
	agent.HardStale:             slog.LevelError,
	agent.Quarantined:           slog.LevelError,
	agent.QuarantineFailed:      slog.LevelError,
	agent.Degraded:              slog.LevelWarn,
	agent.MirrorUnusable:        slog.LevelWarn,
	agent.MirrorFailed:          slog.LevelWarn,
	agent.ClockSkew:             slog.LevelWarn,
	reconcile.UnprovenPeer:      slog.LevelWarn,
	reconcile.EvictedPeer:       slog.LevelWarn,
	agent.VerifyFailed:          slog.LevelWarn,
	agent.EnforcingOnStaleState: slog.LevelWarn,
	agent.InterfaceUnavailable:  slog.LevelWarn,
	agent.ControlPlaneFight:     slog.LevelWarn,
	agent.PeerRefused:           slog.LevelWarn,
	agent.AdoptedFromPeer:       slog.LevelWarn,
	agent.NoStateYet:            slog.LevelWarn,
	agent.ProviderClaim:         slog.LevelWarn,
	// A proven peer may simply not have connected yet, and installing it is
	// not the watchdog's job. Its absence is routine (G4 non-goal).
	reconcile.MissingPeer: slog.LevelInfo,
}

// report preserves the event's details while giving it its chosen level.
func report(logger *slog.Logger, event agent.Event) {
	attrs := []any{"kind", event.Kind}
	if event.Peer != nil {
		attrs = append(attrs, "key", event.Peer.Key.String())
		if len(event.Peer.AllowedIPs) > 0 {
			attrs = append(attrs, "allowed_ips", fmt.Sprint(event.Peer.AllowedIPs))
		}
		if event.Peer.Endpoint.IsValid() {
			attrs = append(attrs, "endpoint", event.Peer.Endpoint.String())
		}
	}
	level, ok := eventLevels[event.Kind]
	if !ok {
		// An unknown kind means the reporting contract was broken. Make that
		// visible even if a binary was built without running the tests.
		level = slog.LevelError
	}
	logger.Log(context.Background(), level, event.Message, attrs...)
}

func newLogger(asJSON bool) *slog.Logger {
	if asJSON {
		return slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// pick returns the first non-empty value.
func pick(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// serveGossip runs the peer endpoints in the background.
func serveGossip(logger *slog.Logger, addr, mirror, evidence string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		// The usual cause is a tunnel that is not up yet, which is a state
		// worth naming rather than a reason to refuse to run.
		logger.Warn("not gossiping", "addr", addr, "reason", err)
		return
	}
	logger.Info("gossiping", "addr", addr, "mirror", mirror, "evidence", evidence)
	go func() {
		server := &http.Server{
			Handler:           gossip.Handler(mirror, evidence),
			ReadHeaderTimeout: 10 * time.Second,
		}
		if err := server.Serve(listener); err != nil {
			logger.Warn("gossip server stopped", "reason", err)
		}
	}()
}
