package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func deploymentFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "contrib", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Repeated directives can add capabilities or undo a restriction. Keeping
// every value, rather than just the last, makes either change visible.
func deploymentUnit(t *testing.T) map[string][]string {
	t.Helper()
	unit := make(map[string][]string)
	var section string
	for _, line := range strings.Split(deploymentFile(t, "systemd/nornd.service"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" || strings.TrimSpace(key) == "" {
			t.Fatalf("not a unit directive under a section: %q", line)
		}
		key = section + "/" + strings.TrimSpace(key)
		unit[key] = append(unit[key], strings.TrimSpace(value))
	}
	return unit
}

func unitValue(t *testing.T, unit map[string][]string, key string) string {
	t.Helper()
	values := unit["Service/"+key]
	if len(values) != 1 {
		t.Fatalf("Service/%s has %d directives, want exactly one", key, len(values))
	}
	return values[0]
}

// This unit needs netlink access, not a root daemon. An added capability or
// a lost restriction must fail here before an operator installs the file.
func TestTheSystemdUnitKeepsItsHardeningLines(t *testing.T) {
	unit := deploymentUnit(t)
	for key, want := range map[string]string{
		"ExecStart":             "/usr/local/bin/nornd -config /etc/norn/nornd.toml",
		"Restart":               "always",
		"RestartSec":            "2s",
		"DynamicUser":           "yes",
		"AmbientCapabilities":   "CAP_NET_ADMIN",
		"CapabilityBoundingSet": "CAP_NET_ADMIN",
		"NoNewPrivileges":       "yes",
		"ProtectSystem":         "strict",
		"ProtectHome":           "yes",
		"PrivateTmp":            "yes",
		"RuntimeDirectory":      "norn",
		"StateDirectory":        "norn",
		"ReadOnlyPaths":         "/etc/norn",
	} {
		t.Run(key, func(t *testing.T) {
			if got := unitValue(t, unit, key); got != want {
				t.Errorf("Service/%s = %q, want %q", key, got, want)
			}
		})
	}
	for _, user := range unit["Service/User"] {
		if user == "" || user == "root" || user == "0" {
			t.Errorf("the daemon must not run as root: User=%q", user)
		}
	}
	// Restart=always still stops at systemd's start limit -- five starts in
	// ten seconds by default -- and a crash loop that tripped it would leave
	// the interface unwatched until somebody noticed. The limit is lifted, so
	// the restart promise does not rest on RestartSec times the default burst.
	if got := unit["Unit/StartLimitIntervalSec"]; len(got) != 1 || got[0] != "0" {
		t.Errorf("Unit/StartLimitIntervalSec = %q, want exactly one \"0\"", got)
	}
}

func deploymentConfig(t *testing.T) Config {
	t.Helper()
	config, err := LoadConfig(filepath.Join("..", "..", "contrib", "nornd.toml.example"))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

// Observe is deliberate in the shipped file: installing an example must
// not give the daemon permission to write the interface.
func TestTheExampleStartsInObserveMode(t *testing.T) {
	config := deploymentConfig(t)
	if config.Mode != "observe" {
		t.Errorf("example mode = %q, want observe", config.Mode)
	}
	if config.Interface == "" || config.Trust == "" {
		t.Error("the example must name the interface and its trust anchor")
	}
}

type exampleSetting struct {
	value     string
	commented bool
}

// A key mentioned in prose is not an example a reader can enable. Match
// assignments and table headers, including their section and comment state.
func exampleSettings(t *testing.T) map[string]exampleSetting {
	t.Helper()
	settings := make(map[string]exampleSetting)
	var section string
	for _, line := range strings.Split(deploymentFile(t, "nornd.toml.example"), "\n") {
		line = strings.TrimSpace(line)
		commented := strings.HasPrefix(line, "#")
		line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
		key, value, ok := strings.Cut(line, "=")
		if strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]") {
			section = strings.TrimSuffix(strings.TrimPrefix(line, "[["), "]]")
			key, value, ok = section, line, true
		} else if ok {
			key = strings.TrimSpace(key)
			if section != "" {
				key = section + "/" + key
			}
		}
		if !ok {
			continue
		}
		if _, duplicate := settings[key]; duplicate {
			t.Fatalf("the example repeats %q", key)
		}
		settings[key] = exampleSetting{strings.TrimSpace(value), commented}
	}
	return settings
}

func TestTheExampleDocumentsEverySetting(t *testing.T) {
	settings := exampleSettings(t)
	for _, typ := range []reflect.Type{reflect.TypeFor[Config](), reflect.TypeFor[Peer]()} {
		for i := 0; i < typ.NumField(); i++ {
			key := typ.Field(i).Tag.Get("toml")
			if key == "" || key == "-" {
				continue
			}
			if typ == reflect.TypeFor[Peer]() {
				key = "peer/" + key
			}
			if _, ok := settings[key]; !ok {
				t.Errorf("the example has no line for %s.%s (%s)", typ.Name(), typ.Field(i).Name, key)
			}
		}
	}
	for key, setting := range settings {
		switch key {
		case "interface", "trust", "mode", "run_dir", "state_dir":
			if setting.commented {
				t.Errorf("the deployment needs %s set", key)
			}
		default:
			if !setting.commented {
				t.Errorf("optional setting %s must stay commented out", key)
			}
		}
	}
}

func TestTheExampleLeavesDisconnectionAnExplicitChoice(t *testing.T) {
	settings := exampleSettings(t)
	for _, key := range []string{"hard_stale", "allow_no_quorum", "quarantine_command"} {
		if setting, ok := settings[key]; !ok || !setting.commented {
			t.Errorf("%s must be present but commented out", key)
		}
	}
	config := deploymentConfig(t)
	if config.HardStale != "" || config.AllowNoQuorum || len(config.QuarantineCommand) != 0 {
		t.Errorf("the example opts into a break-glass setting: %+v", config)
	}
}

// Runtime files can disappear at boot; the held head and fork evidence
// cannot. The unit and the example must give each the directory it needs.
func TestTheDeploymentPathsAgree(t *testing.T) {
	unit := deploymentUnit(t)
	config := deploymentConfig(t)
	if config.RunDir != DefaultRunDir || config.RunDir != filepath.Join("/run", unitValue(t, unit, "RuntimeDirectory")) {
		t.Errorf("run_dir = %q, want the unit's runtime directory %s", config.RunDir, DefaultRunDir)
	}
	if config.StateDir != DefaultStateDir || config.StateDir != filepath.Join("/var/lib", unitValue(t, unit, "StateDirectory")) {
		t.Errorf("state_dir = %q, want the unit's persistent directory %s", config.StateDir, DefaultStateDir)
	}
	exec := strings.Fields(unitValue(t, unit, "ExecStart"))
	if len(exec) != 3 || exec[1] != "-config" || exec[2] != "/etc/norn/nornd.toml" {
		t.Fatalf("ExecStart must read the installed example: %q", exec)
	}
	if !strings.Contains(deploymentFile(t, "nornd.toml.example"), "# Install this file as "+exec[2]+" ") {
		t.Errorf("the example must name the unit's config installation path %s", exec[2])
	}
	if filepath.Dir(config.Trust) != filepath.Dir(exec[2]) || filepath.Dir(exec[2]) != unitValue(t, unit, "ReadOnlyPaths") {
		t.Errorf("trust %q and config %q must be under the unit's read-only path", config.Trust, exec[2])
	}
	settings := exampleSettings(t)
	if settings["gossip_port"].value != "8100" || DefaultGossipPort != 8100 {
		t.Error("the commented gossip port must match nornd's default")
	}
}
