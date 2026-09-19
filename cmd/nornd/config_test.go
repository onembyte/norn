package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/reconcile"
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
	if config.Interface != "wg0" || config.Mode != "watchdog" {
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
