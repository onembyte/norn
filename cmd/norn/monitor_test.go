package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// `norn monitor` per `LAB.md` §3. The gate line asks for "one notification
// received per rule during the run", which is a lab item -- a real run against
// a real network. What is testable here is that a single round over a real log
// produces alerts, that they reach the configured outputs, and that the status
// page comes up.

func writeMonitorConfig(t *testing.T, extra string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "monitor.toml")
	body := "trust = \"" + filepath.Join(vectors(), "trust.cbor") + "\"\n" +
		"log = \"" + filepath.Join(vectors(), "served") + "\"\n" + extra
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// One round over the fixture's log, with stdout as the only output.
func TestMonitorOnceWritesJSONToStdout(t *testing.T) {
	bin := nornBinary(t)

	out, stderr, err := run(t, bin, "monitor", "-config", writeMonitorConfig(t, ""), "-once")
	if err != nil {
		t.Fatalf("monitor -once: %v\n%s", err, stderr)
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		t.Fatalf("a round over a 90-entry log wrote %d lines:\n%s", len(lines), out)
	}
	rules := map[string]bool{}
	for _, line := range lines {
		var alert map[string]any
		if err := json.Unmarshal([]byte(line), &alert); err != nil {
			t.Fatalf("a line is not JSON (%v): %q", err, line)
		}
		rule, _ := alert["rule"].(string)
		rules[rule] = true
	}
	// The fixture exercises more than one rule, which is what the gate line is
	// really asking to be able to count.
	if len(rules) < 2 {
		t.Errorf("one round produced %d distinct rules: %v", len(rules), rules)
	}
	if !rules["new-entry"] {
		t.Errorf("entries should be reported: %v", rules)
	}
}

// The outputs an operator configures actually receive the alerts.
func TestMonitorDeliversToConfiguredOutputs(t *testing.T) {
	bin := nornBinary(t)
	var mu sync.Mutex
	var received int
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received++
		mu.Unlock()
	}))
	defer sink.Close()

	config := writeMonitorConfig(t, "ntfy = \""+sink.URL+"\"\n")
	if _, stderr, err := run(t, bin, "monitor", "-config", config, "-once"); err != nil {
		t.Fatalf("monitor: %v\n%s", err, stderr)
	}

	mu.Lock()
	defer mu.Unlock()
	if received == 0 {
		t.Error("nothing reached the configured output")
	}
}

// An output being down does not stop the round, and the monitor says which one
// failed rather than going quiet about it.
func TestMonitorSurvivesADeadOutput(t *testing.T) {
	bin := nornBinary(t)
	config := writeMonitorConfig(t, "ntfy = \"http://127.0.0.1:1\"\n")

	out, stderr, err := run(t, bin, "monitor", "-config", config, "-once")
	if err != nil {
		t.Fatalf("a dead output stopped the monitor: %v\n%s", err, stderr)
	}
	if len(strings.TrimSpace(out)) == 0 {
		t.Error("stdout was silenced by another output failing")
	}
	if !strings.Contains(stderr, "could not deliver") {
		t.Errorf("the failing output should be named on stderr:\n%s", stderr)
	}
}

// A config naming something that is not a setting is refused rather than
// half-applied: a typo in an output URL is a monitor that silently never pages.
func TestMonitorRefusesAnUnknownSetting(t *testing.T) {
	bin := nornBinary(t)
	config := writeMonitorConfig(t, "ntfyy = \"http://example.invalid\"\n")

	_, stderr, err := run(t, bin, "monitor", "-config", config, "-once")
	if err == nil {
		t.Fatal("a config with a misspelled setting was accepted")
	}
	if !strings.Contains(stderr, "ntfyy") {
		t.Errorf("the error should name the typo:\n%s", stderr)
	}
}

// Without a trust file there is no network to watch.
func TestMonitorNeedsATrustFile(t *testing.T) {
	bin := nornBinary(t)
	path := filepath.Join(t.TempDir(), "monitor.toml")
	if err := os.WriteFile(path, []byte("log = \"/tmp\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, stderr, err := run(t, bin, "monitor", "-config", path, "-once"); err == nil {
		t.Fatal("a monitor started with no anchor")
	} else if !strings.Contains(stderr, "trust") {
		t.Errorf("the error should say what is missing:\n%s", stderr)
	}
}
