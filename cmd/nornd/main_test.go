package main

import (
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
)

func nornd(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "nornd")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("building nornd: %v\n%s", err, out)
	}
	return bin
}

func vectors() string { return filepath.Join("..", "..", "testdata", "vectors") }

func runNornd(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// Everything unusable is refused before the first cycle, not during it: a
// daemon that started and then failed would look like it was working.
func TestRefusalsBeforeTheFirstCycle(t *testing.T) {
	bin := nornd(t)
	trustFile := filepath.Join(vectors(), "trust.cbor")

	cases := []struct {
		why  string
		args []string
		says string
	}{
		{"no interface", []string{"-trust", trustFile, "-once"}, "-iface is required"},
		{"no trust file", []string{"-iface", "wg-nonexistent0", "-once"}, "-trust is required"},
		{"a mode that is not a mode", []string{"-iface", "wg-nonexistent0",
			"-trust", trustFile, "-mode", "enforce", "-once"}, "not a mode"},
		{"a poll interval of zero", []string{"-iface", "wg-nonexistent0",
			"-trust", trustFile, "-poll", "0s", "-once"}, "poll must be between"},
		{"a trust file that is not there", []string{"-iface", "wg-nonexistent0",
			"-trust", filepath.Join(t.TempDir(), "absent"), "-once"}, "reading the trust file"},
		// S_hard below the staleness default would drop every peer before the
		// network had called the view degraded. Refusing it here proves the
		// flag reaches the parser, not only that the parser is correct.
		{"an S_hard that fires before degraded", []string{"-iface", "wg-nonexistent0",
			"-trust", trustFile, "-hard-stale", "30s", "-once"}, "hard_stale must be at least"},
		{"a negative clock-skew bound", []string{"-iface", "wg-nonexistent0",
			"-trust", trustFile, "-max-skew", "-5m", "-once"}, "max_skew must be positive"},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			out, err := runNornd(t, bin, c.args...)
			if err == nil {
				t.Fatalf("started with %s", c.why)
			}
			if !strings.Contains(out, c.says) {
				t.Errorf("the error should mention %q:\n%s", c.says, out)
			}
		})
	}
}

// An interface that does not exist is a clear failure, not a daemon spinning
// against nothing.
func TestAnAbsentInterfaceIsRefused(t *testing.T) {
	bin := nornd(t)
	out, err := runNornd(t, bin, "-iface", "norn-not-a-real-iface0",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-once")
	if err == nil {
		t.Fatalf("started against an interface that does not exist:\n%s", out)
	}
	if !strings.Contains(out, "norn-not-a-real-iface0") {
		t.Errorf("the error should name the interface:\n%s", out)
	}
}

func TestAnUnreadableConfigIsRefused(t *testing.T) {
	bin := nornd(t)
	path := filepath.Join(t.TempDir(), "nornd.toml")
	if err := os.WriteFile(path, []byte("interface = \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runNornd(t, bin, "-config", path, "-once")
	if err == nil {
		t.Fatalf("started with an unparseable config:\n%s", out)
	}
}

// The config supplies settings and flags override them, so a running node can
// be overridden without editing a file.
func TestFlagsOverrideTheConfig(t *testing.T) {
	bin := nornd(t)
	path := filepath.Join(t.TempDir(), "nornd.toml")
	body := "interface = \"from-config0\"\nmode = \"owner\"\ntrust = \"" +
		filepath.Join(vectors(), "trust.cbor") + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// Both fail (neither interface exists), but the message says which one it
	// tried -- which is what proves the override happened.
	out, _ := runNornd(t, bin, "-config", path, "-once")
	if !strings.Contains(out, "from-config0") {
		t.Errorf("the config's interface was not used:\n%s", out)
	}
	out, _ = runNornd(t, bin, "-config", path, "-iface", "from-flag0", "-once")
	if !strings.Contains(out, "from-flag0") || strings.Contains(out, "from-config0") {
		t.Errorf("the flag did not override the config:\n%s", out)
	}
}

// The mode must be visible before anything can fail, because "it did not
// start" and "it started enforcing" are very different things to be wrong
// about -- and observe being the default is only useful if an operator can see
// that it is in force.
func TestTheModeIsAnnouncedEvenWhenStartupFails(t *testing.T) {
	bin := nornd(t)
	out, err := runNornd(t, bin, "-iface", "norn-not-a-real-iface0",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-once")
	if err == nil {
		t.Fatal("expected this to fail")
	}
	if !strings.Contains(out, "mode=observe") {
		t.Errorf("the default mode was not announced:\n%s", out)
	}
	if !strings.Contains(out, "write nothing") {
		t.Errorf("observe mode should say what it will not do:\n%s", out)
	}

	out, _ = runNornd(t, bin, "-iface", "norn-not-a-real-iface0",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-mode", "owner", "-once")
	if !strings.Contains(out, "mode=owner") {
		t.Errorf("an enforcing mode must be announced too:\n%s", out)
	}
	if strings.Contains(out, "write nothing") {
		t.Error("owner mode claimed it would write nothing")
	}
}

// `GOSSIP.md` part 6 puts the gossip server on the WireGuard address only.
// There is no flag for it, and that is the point: an operator cannot expose a
// node's mirror to the internet by typing the wrong thing, because there is
// nothing to type.
func TestThereIsNoWayToBindGossipToTheWorld(t *testing.T) {
	bin := nornd(t)
	out, _ := runNornd(t, bin, "-h")

	for _, forbidden := range []string{"gossip-listen", "gossip-addr", "gossip-bind"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("-%s exists; the gossip address must come from the interface "+
				"so it cannot be pointed anywhere else:\n%s", forbidden, out)
		}
	}
	// It can be turned off, because a node on a tunnel that does not carry its
	// peers has nobody to gossip with.
	if !strings.Contains(out, "gossip") {
		t.Errorf("there should be a way to turn gossip off:\n%s", out)
	}
}

// SEC-006: `/run` is cleared at boot, so what must outlive one -- the mirror
// whose head a node holds (D-069) and the evidence whose presence is a fork
// freeze (§11) -- lives in a state directory, by default under `/var/lib`.
// The startup line names it, because "where is my freeze kept" is a question
// an operator should be able to answer from the log.
func TestStateLivesWhereARebootLeavesIt(t *testing.T) {
	bin := nornd(t)
	trustFile := filepath.Join(vectors(), "trust.cbor")
	out, _ := runNornd(t, bin, "-iface", "norn-not-a-real-iface0", "-trust", trustFile, "-once")
	if !strings.Contains(out, "state_dir="+DefaultStateDir) || DefaultStateDir != "/var/lib/norn" {
		t.Errorf("the default state directory is not %s under /var/lib:\n%s", DefaultStateDir, out)
	}

	elsewhere := t.TempDir()
	out, _ = runNornd(t, bin, "-iface", "norn-not-a-real-iface0", "-trust", trustFile,
		"-state-dir", elsewhere, "-once")
	if !strings.Contains(out, "state_dir="+elsewhere) {
		t.Errorf("-state-dir was not used:\n%s", out)
	}
}

// Gossip serves the mirror and the evidence from where the agent keeps them,
// not from the run directory: a node serving a directory nothing writes to
// would answer every peer with nothing, which looks exactly like a node with
// nothing to say.
func TestGossipServesFromTheStateDirectory(t *testing.T) {
	mirror, evidence := gossipDirs(Config{RunDir: "/run/norn", StateDir: "/var/lib/norn"})
	if mirror != filepath.Join("/var/lib/norn", "mirror") ||
		evidence != filepath.Join("/var/lib/norn", "fork") {
		t.Errorf("gossip serves %s and %s", mirror, evidence)
	}
}

// The daemon's wiring, end to end for one cycle: the state directory it was
// given is the one the agent writes its mirror to, and the run directory keeps
// only what is published. A flag that reached the startup line and not the
// agent would be a setting that says one thing and does another.
func TestTheDaemonHandsItsStateDirectoryToTheAgent(t *testing.T) {
	previous := openDevice
	openDevice = func(string) (peertable.Device, error) { return peertable.NewFake(), nil }
	t.Cleanup(func() { openDevice = previous })

	runDir, stateDir := t.TempDir(), t.TempDir()
	config := Config{Interface: "norn-test0", Trust: filepath.Join(vectors(), "trust.cbor"),
		Log: filepath.Join(vectors(), "served"), RunDir: runDir, StateDir: stateDir}
	config.SetGossipPort(0, true)
	cycle, _, err := build(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := cycle.Once(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, proven.MirrorDir, "checkpoint")); err != nil {
		t.Errorf("the agent did not keep its mirror in the state directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, proven.FileName)); err != nil {
		t.Errorf("proven.json is not in the run directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, proven.MirrorDir)); err == nil {
		t.Error("the mirror was written to the run directory")
	}
}
