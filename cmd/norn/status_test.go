package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/trust"
)

func verifiedStatus(t *testing.T) (*trust.Trust, *logclient.Result) {
	t.Helper()
	anchor, err := loadAnchor(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := logclient.Verify(logclient.Dir(filepath.Join(vectors(), "served")), anchorFor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	return anchor, result
}

func renderedStatus(t *testing.T, anchor *trust.Trust, result *logclient.Result, wall time.Time) string {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "status")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	original := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = original }()
	printStatus(anchor, result, 0, wall)
	raw, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestStatusJudgesExpiryAtWitnessTime(t *testing.T) {
	anchor, result := verifiedStatus(t)
	if result.QuorumTime == nil {
		t.Fatal("the fixture must have a witness quorum time")
	}
	witness := *result.QuorumTime
	d := result.State.Devices["nas"]
	d.Status = state.StatusActive
	d.Expires = uint64(witness.Add(time.Hour).Unix())
	result.State.Devices = map[string]state.Device{"nas": d}
	out := renderedStatus(t, anchor, result, witness.Add(2*time.Hour))
	if !strings.Contains(out, "1 proven, 0 revoked, 0 expired") {
		t.Errorf("the local clock expired an active device:\n%s", out)
	}
	if !strings.Contains(out, "expiry judged at "+witness.UTC().Format(time.RFC3339)) {
		t.Errorf("status omits the witness instant used for expiry:\n%s", out)
	}
}

func TestStatusDoesNotJudgeExpiryWithoutWitnessTime(t *testing.T) {
	anchor, result := verifiedStatus(t)
	anchor.Policy = "quorum none\n"
	result.QuorumTime = nil
	d := result.State.Devices["nas"]
	d.Status = state.StatusActive
	d.Expires = 1
	result.State.Devices = map[string]state.Device{"nas": d}
	out := renderedStatus(t, anchor, result, time.Unix(1_900_000_000, 0))
	if !strings.Contains(out, "1 proven, 0 revoked, 0 expired") {
		t.Errorf("status guessed expiry without a witness clock:\n%s", out)
	}
	if !strings.Contains(out, "no witness time; expiry not judged") {
		t.Errorf("status omits the missing expiry clock:\n%s", out)
	}
}

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
		servedSize(t) + " entries", "peers", "proven", "revoked", "expired"} {
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
// view is. Witness time is the clock (GOSSIP.md part 5), so `status` reports
// the instant a quorum vouched for -- and labels the age it derives, because
// a one-shot command has no monotonic history and can only subtract using the
// machine's own clock, which is not evidence (A11).
func TestStatusReportsWitnessTimeAndLabelsTheLocalClock(t *testing.T) {
	out := statusOutput(t)
	if !strings.Contains(out, "cosigned") {
		t.Errorf("status must report the instant the witnesses vouched for:\n%s", out)
	}
	// Which witnesses, and how many the policy needed: "2 of 3" is the fact an
	// operator is actually checking.
	if !strings.Contains(out, "quorum") {
		t.Errorf("status must say what the policy required:\n%s", out)
	}
	// Any age it prints is the local clock's opinion and must say so.
	if strings.Contains(out, "age") && !strings.Contains(out, "this machine's clock") {
		t.Errorf("an age must be labelled as the local clock's:\n%s", out)
	}
	if !strings.Contains(out, "A11") {
		t.Errorf("the reason the local clock is not evidence should be on screen:\n%s", out)
	}
}

// A log no witness has cosigned still has to produce a status, and it must say
// `UNKNOWN` rather than a state it cannot compute.
func TestStatusRefusesToInventFreshnessWithoutWitnesses(t *testing.T) {
	line := freshnessLine(nil, nil, "quorum home", time.Unix(1_760_000_000, 0))
	if !strings.Contains(line, "UNKNOWN") {
		t.Errorf("freshness must be unknown with no cosignatures:\n%s", line)
	}
	// It may explain what it cannot compute; it may not claim one.
	for _, forbidden := range []string{"freshness   fresh", "freshness   degraded",
		"freshness   hard", "cosigned 2", "age "} {
		if strings.Contains(line, forbidden) {
			t.Errorf("status claimed %q with no witness time:\n%s", forbidden, line)
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
	// Every rendered row, not only the datable ones: an entry that does not
	// decode has no timestamp to show and is still one of the recent entries.
	lines := 0
	for _, line := range strings.Split(tail, "\n") {
		if strings.HasPrefix(line, "  ") && strings.TrimSpace(line) != "" {
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
