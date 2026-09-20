package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/monitor"
)

// monitorConfig is `monitor.toml` (`LAB.md` §3).
//
// Every output is optional and stdout is unconditional, so the zero value of
// this struct is a working monitor that writes JSON — which is the
// configuration somebody should be able to start with.
type monitorConfig struct {
	// Trust is the network's anchor. Required: a monitor without one is
	// watching nothing in particular.
	Trust string `toml:"trust"`
	// Log is the log to read; empty means the anchor's first `log_urls` entry.
	Log string `toml:"log"`
	// Nodes are the nornds to watch, at their tunnel addresses.
	Nodes []monitorNode `toml:"node"`

	// Every is how often to run a round. Default: DefaultMonitorEvery.
	Every string `toml:"every"`

	// Outputs. All optional; stdout is always on.
	Ntfy          string   `toml:"ntfy"`
	NtfyTags      []string `toml:"ntfy_tags"`
	HomeAssistant string   `toml:"home_assistant"`
	Alertmanager  string   `toml:"alertmanager"`

	// Email, if a relay is available.
	EmailFrom     string   `toml:"email_from"`
	EmailTo       []string `toml:"email_to"`
	EmailServer   string   `toml:"email_server"`
	EmailUsername string   `toml:"email_username"`
	EmailPassword string   `toml:"email_password"`

	// StatusListen is where to serve the status page. Empty means do not.
	StatusListen string `toml:"status_listen"`

	// Thresholds, for a homelab that wants different ones.
	HeartbeatMissing string `toml:"heartbeat_missing"`
	MaxAnchorLag     string `toml:"max_anchor_lag"`
}

type monitorNode struct {
	Name string `toml:"name"`
	URL  string `toml:"url"`
}

// DefaultMonitorEvery is how often a round runs when nothing says otherwise.
const DefaultMonitorEvery = 60 * time.Second

// monitorCmd watches a network and says what it sees.
//
// It is an enrolled peer, not a privileged one: everything it reads it
// verifies under the same anchor a node uses, and nothing it concludes reaches
// anybody's peer table (`LAB.md` §3).
func monitorCmd(args []string) error {
	fs := newFlagSet("monitor")
	configPath := fs.String("config", "", "a monitor.toml (required)")
	once := fs.Bool("once", false, "run one round and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		fs.Usage()
		return fmt.Errorf("-config is required")
	}

	var config monitorConfig
	meta, err := toml.DecodeFile(*configPath, &config)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *configPath, err)
	}
	// A misspelled setting is refused rather than ignored: a typo in an output
	// URL is a monitor that silently never pages, which is worse than one that
	// refuses to start.
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return fmt.Errorf("%s: unknown setting %q", *configPath, undecoded[0].String())
	}
	if config.Trust == "" {
		return fmt.Errorf("%s: `trust` is required; a monitor without an anchor is "+
			"watching nothing in particular", *configPath)
	}

	anchor, err := loadAnchor(config.Trust)
	if err != nil {
		return err
	}
	location := config.Log
	if location == "" {
		location = anchor.LogURLs[0]
	}
	fetcher, err := logclient.Open(location)
	if err != nil {
		return err
	}

	rules := monitor.Default()
	if config.HeartbeatMissing != "" {
		if rules.HeartbeatMissing, err = time.ParseDuration(config.HeartbeatMissing); err != nil {
			return fmt.Errorf("heartbeat_missing: %w", err)
		}
	}
	if config.MaxAnchorLag != "" {
		if rules.MaxAnchorLag, err = time.ParseDuration(config.MaxAnchorLag); err != nil {
			return fmt.Errorf("max_anchor_lag: %w", err)
		}
	}
	every := DefaultMonitorEvery
	if config.Every != "" {
		if every, err = time.ParseDuration(config.Every); err != nil {
			return fmt.Errorf("every: %w", err)
		}
	}

	nodes := make([]monitor.Node, 0, len(config.Nodes))
	for _, node := range config.Nodes {
		nodes = append(nodes, monitor.Node{Name: node.Name, URL: node.URL})
	}
	sinks := sinksFor(config)

	watcher := monitor.New(anchor, rules)
	status := &monitor.Status{Network: anchor}
	if config.StatusListen != "" {
		if err := serveStatus(config.StatusListen, status); err != nil {
			return err
		}
	}

	for {
		alerts := watcher.Round(fetcher, nodes)
		status.Alerts = alerts
		for _, alert := range alerts {
			for _, failure := range sinks.Send(alert) {
				// Said out loud, not swallowed: an output nobody knows is
				// broken is an output nobody is reading.
				fmt.Fprintf(os.Stderr, "norn: could not deliver %s: %v\n",
					alert.Rule, failure)
			}
		}
		if *once {
			return nil
		}
		time.Sleep(every)
	}
}

// sinksFor builds the outputs, with stdout always present.
func sinksFor(config monitorConfig) monitor.Fanout {
	sinks := monitor.Fanout{monitor.Stdout(os.Stdout)}
	if config.Ntfy != "" {
		sinks = append(sinks, monitor.Ntfy(config.Ntfy, config.NtfyTags))
	}
	if config.HomeAssistant != "" {
		sinks = append(sinks, monitor.HomeAssistant(config.HomeAssistant))
	}
	if config.Alertmanager != "" {
		sinks = append(sinks, monitor.Alertmanager(config.Alertmanager))
	}
	if config.EmailServer != "" && len(config.EmailTo) > 0 {
		sinks = append(sinks, monitor.Email(monitor.EmailConfig{
			From: config.EmailFrom, To: config.EmailTo, Server: config.EmailServer,
			Username: config.EmailUsername, Password: config.EmailPassword,
		}))
	}
	return sinks
}

// serveStatus starts the read-only page in the background.
//
// A failure to bind is fatal, unlike a failure to deliver an alert: an
// operator who asked for a status page and did not get one would go looking
// for it during an incident, which is the worst possible moment to discover a
// typo in a port.
func serveStatus(addr string, status *monitor.Status) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("status page: %w", err)
	}
	fmt.Fprintf(os.Stderr, "norn: status page on http://%s\n", listener.Addr())
	go func() {
		server := &http.Server{
			Handler:           status.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		if err := server.Serve(listener); err != nil {
			fmt.Fprintln(os.Stderr, "norn: status page stopped:", err)
		}
	}()
	return nil
}
