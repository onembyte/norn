package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/reconcile"

	"github.com/onembyte/norn/internal/freshness"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nornd.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAConfigAnOperatorWouldWrite(t *testing.T) {
	path := write(t, `
interface = "wg0"
mode      = "watchdog"
poll      = "200ms"
trust     = "/etc/norn/norn.trust"
log       = "https://log.example/net"
run_dir   = "/run/norn"
state_dir = "/var/lib/norn"

[[peer]]
device_id   = "pi-cam"
allowed_ips = ["10.9.0.14/32"]
endpoint    = "192.0.2.14:51820"
keepalive   = 25

[[peer]]
device_id   = "nas"
allowed_ips = ["10.9.0.2/32", "fd00::2/128"]
`)
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Interface != "wg0" || config.Mode != "watchdog" ||
		config.StateDir != "/var/lib/norn" {
		t.Errorf("config = %+v", config)
	}

	static, err := config.Static()
	if err != nil {
		t.Fatal(err)
	}
	if len(static.Peers) != 2 {
		t.Fatalf("peers = %+v", static.Peers)
	}
	cam := static.Peers["pi-cam"]
	if cam.Endpoint.String() != "192.0.2.14:51820" || cam.Keepalive != 25*time.Second {
		t.Errorf("pi-cam = %+v", cam)
	}
	if len(static.Peers["nas"].AllowedIPs) != 2 {
		t.Errorf("nas = %+v", static.Peers["nas"])
	}
}

// A misspelled setting must stop the daemon, not be shrugged off: a
// misspelled `mode` that silently left a node observing would be a node
// quietly not enforcing.
func TestAnUnknownSettingIsRefused(t *testing.T) {
	path := write(t, `interface = "wg0"`+"\n"+`moed = "owner"`+"\n")
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("a misspelled setting was accepted")
	}
	if !strings.Contains(err.Error(), "moed") {
		t.Errorf("the error should name it: %v", err)
	}
}

// There is no key in a [[peer]] block, and there cannot be one.
func TestAPeerBlockCannotCarryAKey(t *testing.T) {
	path := write(t, `
[[peer]]
device_id  = "intruder"
public_key = "cEXAMPLEkeythatshouldneverwork0000000000000="
`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("a [[peer]] block was allowed to name a key")
	}
}

func TestBadPeerBlocks(t *testing.T) {
	cases := map[string]string{
		"no device_id":       "[[peer]]\nallowed_ips = [\"10.9.0.1/32\"]\n",
		"two of one device":  "[[peer]]\ndevice_id=\"a\"\n[[peer]]\ndevice_id=\"a\"\n",
		"not a CIDR":         "[[peer]]\ndevice_id=\"a\"\nallowed_ips=[\"10.9.0.1\"]\n",
		"not host:port":      "[[peer]]\ndevice_id=\"a\"\nendpoint=\"somewhere\"\n",
		"negative keepalive": "[[peer]]\ndevice_id=\"a\"\nkeepalive=-5\n",
	}
	for why, body := range cases {
		t.Run(why, func(t *testing.T) {
			config, err := LoadConfig(write(t, body))
			if err != nil {
				return // refused at parse time, which is also fine
			}
			if _, err := config.Static(); err == nil {
				t.Errorf("accepted a [[peer]] block with %s", why)
			}
		})
	}
}

// The default is load-bearing: a daemon that enforced because a field was
// missing would take a network down on a typo.
func TestTheDefaultModeIsObserve(t *testing.T) {
	mode, err := ParseMode("")
	if err != nil {
		t.Fatal(err)
	}
	if mode != reconcile.Observe {
		t.Fatalf("mode = %q with nothing configured", mode)
	}
	for _, good := range []string{"observe", "owner", "watchdog"} {
		if _, err := ParseMode(good); err != nil {
			t.Errorf("%s: %v", good, err)
		}
	}
	// And a near miss is an error, not a silent fallback to observe.
	for _, bad := range []string{"enforce", "Owner", "watch", "off"} {
		if _, err := ParseMode(bad); err == nil {
			t.Errorf("%q was accepted as a mode", bad)
		}
	}
}

func TestPollBounds(t *testing.T) {
	if got, err := ParsePoll(""); err != nil || got != DefaultPoll {
		t.Errorf("default poll = %v, %v", got, err)
	}
	if got, err := ParsePoll("200ms"); err != nil || got != 200*time.Millisecond {
		t.Errorf("poll = %v, %v", got, err)
	}
	// A zero is a busy loop; a day is a window an intruder lives inside.
	for _, bad := range []string{"0s", "1ms", "48h", "soon"} {
		if _, err := ParsePoll(bad); err == nil {
			t.Errorf("%q was accepted as a poll interval", bad)
		}
	}
}

func TestFightSettings(t *testing.T) {
	// The default is alarm: keep evicting, keep alarming, keep the network up.
	policy, _, _, err := Config{}.FightSettings()
	if err != nil || policy != "alarm" {
		t.Fatalf("default policy = %q, %v", policy, err)
	}

	config := Config{FightPolicy: "quarantine", FightThreshold: 5, FightWindow: "90s"}
	policy, threshold, window, err := config.FightSettings()
	if err != nil {
		t.Fatal(err)
	}
	if policy != "quarantine" || threshold != 5 || window != 90*time.Second {
		t.Errorf("settings = %q, %d, %s", policy, threshold, window)
	}

	for _, bad := range []Config{
		{FightPolicy: "shutdown"},
		{FightThreshold: -1},
		{FightWindow: "soon"},
		{FightWindow: "0s"},
	} {
		if _, _, _, err := bad.FightSettings(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// Taking a network down is a break-glass action, so an operator must be able
// to read exactly what will run -- and replace it.
func TestQuarantineCommandIsExplicitAndSubstituted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	config := Config{QuarantineCommand: []string{"false", "{iface}", "down"}}

	action, err := config.QuarantineFor("wg0", logger)
	if err != nil {
		t.Fatal(err)
	}
	// `false` exits non-zero, so the error must carry what was run.
	err = action("a fight")
	if err == nil {
		t.Fatal("a failing quarantine command reported success")
	}
	if !strings.Contains(err.Error(), "wg0") {
		t.Errorf("the error should name the command that ran: %v", err)
	}

	ok, err := Config{QuarantineCommand: []string{"true"}}.QuarantineFor("wg0", logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := ok("a fight"); err != nil {
		t.Errorf("a successful command reported failure: %v", err)
	}
}

// On a platform where Norn cannot assume a command, it says so rather than
// guessing at something that might not take the interface down at all.
func TestQuarantineNeedsACommandWhereThereIsNoDefault(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := Config{}.QuarantineFor("wg0", logger)
	if runtime.GOOS == "linux" {
		if err != nil {
			t.Fatalf("linux has a documented default: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("assumed a quarantine command on %s", runtime.GOOS)
	}
	if !strings.Contains(err.Error(), "quarantine_command") {
		t.Errorf("the error should say what to configure: %v", err)
	}
}

// S_hard is the one setting that lets a node disconnect itself, so it is
// off unless an operator writes it down, and refused if it would fire before
// `degraded` ever does.
func TestParseHardStale(t *testing.T) {
	for _, tc := range []struct {
		text string
		want time.Duration
	}{
		{"", 0}, // opt-in: absent means never
		{"0", 0},
		{"6h", 6 * time.Hour},
	} {
		got, err := ParseHardStale(tc.text)
		if err != nil {
			t.Errorf("%q: %v", tc.text, err)
		}
		if got != tc.want {
			t.Errorf("%q = %v, want %v", tc.text, got, tc.want)
		}
	}

	// Shorter than the §4.5 staleness default it would drop every peer before
	// the network had even called the view degraded -- almost certainly a
	// typo, and an expensive one.
	for _, bad := range []string{"nonsense", "-1h", "30s"} {
		if _, err := ParseHardStale(bad); err == nil {
			t.Errorf("%q was accepted as S_hard", bad)
		}
	}
}

func TestParseMaxSkew(t *testing.T) {
	got, err := ParseMaxSkew("")
	if err != nil || got != 0 {
		t.Errorf("an absent max_skew must leave the default in place, got %v, %v", got, err)
	}
	if got, err := ParseMaxSkew("30m"); err != nil || got != 30*time.Minute {
		t.Errorf("max_skew = %v, %v", got, err)
	}
	for _, bad := range []string{"nope", "-5m"} {
		if _, err := ParseMaxSkew(bad); err == nil {
			t.Errorf("%q was accepted as Δclock", bad)
		}
	}
}

// A stale node tries harder -- but only ever harder. A node already polling
// four times a second must not be slowed to once every ten because its view
// went stale, which is what a naive "degraded means 10s" would do.
func TestDegradedPollingOnlySpeedsUp(t *testing.T) {
	for _, tc := range []struct {
		interval time.Duration
		state    string
		want     time.Duration
	}{
		{200 * time.Millisecond, freshness.Fresh, 200 * time.Millisecond},
		{200 * time.Millisecond, freshness.Degraded, 200 * time.Millisecond},
		{5 * time.Minute, freshness.Fresh, 5 * time.Minute},
		{5 * time.Minute, freshness.Degraded, DegradedPoll},
		{5 * time.Minute, freshness.HardStale, DegradedPoll},
		{5 * time.Minute, freshness.Unknown, 5 * time.Minute},
	} {
		if got := nextPoll(tc.interval, tc.state); got != tc.want {
			t.Errorf("nextPoll(%s, %s) = %s, want %s", tc.interval, tc.state, got, tc.want)
		}
	}
}

// --- D-060 -------------------------------------------------------------
//
// Before D-060 this guard's stated reason was that a hard limit below the
// network's `staleness` "would drop every peer before the network had even
// called the view degraded, which is a typo with an outage attached". D-060
// makes that configuration legitimate and indeed the point: `S_hard` is the
// node's own floor, and the network cannot raise it. The numeric floor stays,
// but only as a typo guard.

func TestAHardLimitTighterThanTheNetworksIsAccepted(t *testing.T) {
	// The configuration D1 is about: the fixture's genesis sets `staleness`
	// to 600 and a later `params` entry raises it to 900, so 700 is a sensible
	// choice that the network later overtakes.
	got, err := ParseHardStale("700s")
	if err != nil {
		t.Fatalf("a hard limit tighter than the network's staleness must be "+
			"accepted — it is the whole point of a local floor: %v", err)
	}
	if got != 700*time.Second {
		t.Errorf("parsed %s, want 700s", got)
	}
}

func TestTheHardLimitFloorIsATypoGuardAndSaysSo(t *testing.T) {
	_, err := ParseHardStale("5s")
	if err == nil {
		t.Fatal("a five-second hard limit must be refused; it drops every peer " +
			"whenever the log is five seconds stale")
	}
	// The message must not tell the operator that being below the network's
	// staleness is the fault, because after D-060 it is not.
	for _, wrong := range []string{"degraded", "staleness default"} {
		if strings.Contains(err.Error(), wrong) {
			t.Errorf("the refusal still explains itself with %q, which D-060 "+
				"makes wrong: a hard limit below the network's staleness is "+
				"legitimate. Got: %v", wrong, err)
		}
	}
}

// H2-c: the network budgets are settings, each refused when absurd -- a
// slipped unit would make a node that never reaches its peers or never
// finishes a verification, and nothing would say so.
func TestNetworkBudgetsAreBounded(t *testing.T) {
	type parser struct {
		name  string
		parse func(string) (time.Duration, error)
		good  string
		want  time.Duration
		bad   []string
	}
	for _, p := range []parser{
		{"peer_timeout", ParsePeerTimeout, "2s", 2 * time.Second, []string{"10ms", "5m", "-1s", "soon"}},
		{"round_budget", ParseRoundBudget, "8s", 8 * time.Second, []string{"10ms", "1h", "-1s", "soon"}},
		{"verify_budget", ParseVerifyBudget, "2m", 2 * time.Minute, []string{"100ms", "24h", "-1s", "soon"}},
	} {
		t.Run(p.name, func(t *testing.T) {
			if got, err := p.parse(""); err != nil || got != 0 {
				t.Errorf("an absent %s must leave the default in place, got %v, %v", p.name, got, err)
			}
			if got, err := p.parse(p.good); err != nil || got != p.want {
				t.Errorf("%s = %v, %v; want %v", p.name, got, err, p.want)
			}
			for _, bad := range p.bad {
				if _, err := p.parse(bad); err == nil {
					t.Errorf("%q was accepted as %s", bad, p.name)
				}
			}
		})
	}
}
