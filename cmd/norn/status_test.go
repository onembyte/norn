package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func statusOutput(t *testing.T, args ...string) string {
	t.Helper()
	bin := nornBinary(t)
	full := append([]string{"status", "-trust", filepath.Join(vectors(), "trust.cbor"),
		"-log", filepath.Join(vectors(), "served")}, args...)
	out, err := exec.Command(bin, full...).CombinedOutput()
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	return string(out)
}

func TestStatusReportsTheNetworkAndItsPeers(t *testing.T) {
	out := statusOutput(t)
	for _, want := range []string{"norn-testnet", "norn/nzxx", "anchor", "checkpoint",
		"90 entries", "peers", "proven", "revoked", "expired"} {
		if !strings.Contains(out, want) {
			t.Errorf("status omits %q:\n%s", want, out)
		}
	}
	// Devices the fixture makes active, and one it revokes.
	for _, want := range []string{"nas", "pi-cam", "laptop"} {
		if !strings.Contains(out, want) {
			t.Errorf("status omits device %q", want)
		}
	}
}

// The heart of this checkpoint: a node must not pretend to know how fresh its
// view is. Witness time is the clock (GOSSIP.md part 5) and there are no
// cosignatures yet, so the answer is UNKNOWN and the reason is on screen.
func TestStatusRefusesToInventFreshness(t *testing.T) {
	out := statusOutput(t)
	if !strings.Contains(out, "freshness   UNKNOWN") {
		t.Errorf("freshness must be reported as unknown:\n%s", out)
	}
	for _, want := range []string{"cosignature", "clock is", "A11"} {
		if !strings.Contains(out, want) {
			t.Errorf("the reason should be stated (%q missing):\n%s", want, out)
		}
	}
	// And it must not claim a state it cannot compute.
	for _, forbidden := range []string{"freshness   fresh", "freshness   degraded", "seconds old"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("status claimed %q with no witness time:\n%s", forbidden, out)
		}
	}
}

// UX rule 5: the last entries in plain words.
func TestStatusReadsTheLogBackInWords(t *testing.T) {
	out := statusOutput(t, "-recent", "8")
	if !strings.Contains(out, "recent") {
		t.Fatalf("no recent section:\n%s", out)
	}
	tail := out[strings.Index(out, "recent"):]
	lines := 0
	for _, line := range strings.Split(tail, "\n") {
		if strings.HasPrefix(line, "  ") && strings.Contains(line, "ago") {
			lines++
		}
	}
	if lines != 8 {
		t.Errorf("asked for 8 recent entries, got %d:\n%s", lines, tail)
	}
	if !strings.Contains(tail, "advisory") {
		t.Error("the times are the signer's clock and the output should say so")
	}
	// A refused entry must be marked as refused, or reading the log back would
	// show things that never took effect as though they had.
	if !strings.Contains(tail, "REFUSED") {
		t.Errorf("the fixture's tail contains refused entries; they are not marked:\n%s", tail)
	}
}

func TestStatusNeedsAnAnchor(t *testing.T) {
	bin := nornBinary(t)
	out, err := exec.Command(bin, "status", "-log", filepath.Join(vectors(), "served")).CombinedOutput()
	if err == nil {
		t.Fatal("reported status with no trust file")
	}
	if !strings.Contains(string(out), "-trust is required") {
		t.Errorf("the error should say what is missing:\n%s", out)
	}
}

// status verifies like everything else: an unreachable log is not "all quiet".
func TestStatusRefusesAnUnreachableLog(t *testing.T) {
	bin := nornBinary(t)
	out, err := exec.Command(bin, "status", "-trust", filepath.Join(vectors(), "trust.cbor"),
		"-log", filepath.Join(t.TempDir(), "nothing")).CombinedOutput()
	if err == nil {
		t.Fatalf("reported status from a log that is not there:\n%s", out)
	}
}
