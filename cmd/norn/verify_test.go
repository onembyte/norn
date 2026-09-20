package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The CLI is where a person meets the protocol, so these tests care about what
// it refuses and what it says, not only that it runs.

func nornBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "norn")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building norn: %v\n%s", err, out)
	}
	return bin
}

func vectors() string { return filepath.Join("..", "..", "testdata", "vectors") }

func TestVerifyRefusesWithoutAnAnchor(t *testing.T) {
	out, err := exec.Command(nornBinary(t), "verify", "-log", vectors()+"/served").CombinedOutput()
	if err == nil {
		t.Fatal("verifying without a trust file must fail")
	}
	if !strings.Contains(string(out), "-trust is required") {
		t.Errorf("the error should say what is missing, got:\n%s", out)
	}
}

func TestVerifyRefusesAnUnusableAnchor(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "trust.cbor")
	src, err := os.ReadFile(filepath.Join(vectors(), "trust-bad", "07-no-witnesses.cbor"))
	if err != nil {
		t.Skip("trust-bad vector not present")
	}
	if err := os.WriteFile(bad, src, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(nornBinary(t), "verify", "-trust", bad,
		"-log", filepath.Join(vectors(), "served")).CombinedOutput()
	if err == nil {
		t.Fatal("an anchor that fails validation must be refused")
	}
	if !strings.Contains(string(out), "not a usable anchor") {
		t.Errorf("unexpected error:\n%s", out)
	}
}

func TestVerifyReportsAnUnknownCommandClearly(t *testing.T) {
	out, _ := exec.Command(nornBinary(t), "frobnicate").CombinedOutput()
	if !strings.Contains(string(out), "unknown command") || !strings.Contains(string(out), "verify") {
		t.Errorf("an unknown command should name itself and list the real ones, got:\n%s", out)
	}
}

func TestVerifyRefusesALogThatDoesNotMatchTheAnchor(t *testing.T) {
	// The shipped served log is signed for the fixture network, but the
	// fixture trust file pins the fixture genesis -- so pointing verify at a
	// directory with no log at all must fail rather than report an empty
	// network as if it were healthy.
	empty := t.TempDir()
	out, err := exec.Command(nornBinary(t), "verify",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", empty).CombinedOutput()
	if err == nil {
		t.Fatalf("an unreachable log must fail, got:\n%s", out)
	}
}

// `norn verify --anchored` (D-009, PLAN's Phase 4 gate). Advisory: it reports,
// it never decides, and a network with no anchor is not a network with a
// problem.
func TestVerifyAnchoredReportsTheAnchor(t *testing.T) {
	bin := nornBinary(t)
	log := anchoredLog(t)

	out, stderr, err := run(t, bin, "verify", "-trust",
		filepath.Join(vectors(), "trust.cbor"), "-log", log, "-anchored")
	if err != nil {
		t.Fatalf("verify -anchored: %v\n%s", err, stderr)
	}
	if !strings.Contains(out, "800000") {
		t.Errorf("the block the proof commits into should be reported:\n%s", out)
	}
	// And it must not sound like Norn checked a blockchain.
	if !strings.Contains(out, "not checked here") {
		t.Errorf("the summary must say what was not checked:\n%s", out)
	}
}

// A log with no anchor is reported as such, and verification still succeeds:
// anchoring is advisory, and a node that refused a perfectly good log for
// want of an optional extra would be enforcing the opposite of D-009.
func TestVerifyAnchoredIsAdvisory(t *testing.T) {
	bin := nornBinary(t)

	out, stderr, err := run(t, bin, "verify", "-trust",
		filepath.Join(vectors(), "trust.cbor"),
		"-log", filepath.Join(vectors(), "served"), "-anchored")
	if err != nil {
		t.Fatalf("a log with no anchor must still verify: %v\n%s", err, stderr)
	}
	if !strings.Contains(out, "no anchor") {
		t.Errorf("the absence should be reported:\n%s", out)
	}
}

// An anchor that does not belong to this checkpoint is reported loudly. It is
// still advisory -- it does not change what the log proves -- but a stamp for
// other bytes is exactly the sign of a checkpoint edited after stamping.
func TestVerifyAnchoredReportsAMismatchedProof(t *testing.T) {
	bin := nornBinary(t)
	log := anchoredLog(t)
	// The sample proof is over an unrelated digest.
	sample, err := os.ReadFile(filepath.Join(vectors(), "anchors", "sample.ots"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(log, "anchors", "90.ots"), sample, 0o644); err != nil {
		t.Fatal(err)
	}

	out, stderr, _ := run(t, bin, "verify", "-trust",
		filepath.Join(vectors(), "trust.cbor"), "-log", log, "-anchored")
	combined := out + stderr
	if !strings.Contains(combined, "different document") {
		t.Errorf("a proof for other bytes should be named as such:\n%s", combined)
	}
}

// anchoredLog is the fixture's served log with its OpenTimestamps proof in
// place, which is the layout SPEC §6 describes: `anchors/<size>.ots`.
func anchoredLog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(vectors(), "served")
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dir, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "anchors"), 0o755); err != nil {
		t.Fatal(err)
	}
	proof, err := os.ReadFile(filepath.Join(vectors(), "anchors", "checkpoint-90.ots"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchors", "90.ots"), proof, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// --- Cold-model gate run 5, defect G2 (6.5b) -----------------------------
//
// §12.1 claimed the suite refused an unsigned checkpoint, one signed by
// another key, one under another origin, a short quorum, an uncosigned head
// and a forged cosignature. Every one of those was a Go test in this
// repository and none of them was a file. Run 5's implementer therefore built
// a verifier that never checked a note or cosignature signature and passed all
// 597 checks. These are the same refusals, as bytes a second implementer
// actually receives.

func badCheckpointCases(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "checkpoints-bad", "cases.json"))
	if err != nil {
		t.Fatalf("read checkpoints-bad/cases.json: %v", err)
	}
	var doc struct {
		Cases []string `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

// servedWithCheckpoint serves the real log under a checkpoint that must not be
// believed. Everything else about the log is honest, so a refusal can only
// come from the checkpoint.
func servedWithCheckpoint(t *testing.T, checkpoint string) string {
	t.Helper()
	dir := anchoredLog(t)
	body, err := os.ReadFile(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEveryBadCheckpointVectorIsRefused(t *testing.T) {
	cases := badCheckpointCases(t)
	if len(cases) < 8 {
		t.Fatalf("checkpoints-bad ships %d cases; §12.1 names more than that", len(cases))
	}
	bin := nornBinary(t)
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			dir := servedWithCheckpoint(t,
				filepath.Join(vectors(), "checkpoints-bad", name+".checkpoint"))
			out, err := exec.Command(bin, "verify",
				"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", dir).CombinedOutput()
			if err == nil {
				t.Fatalf("accepted %s, which must be refused:\n%s", name, out)
			}
		})
	}
}

// The control: the same harness accepts the honest checkpoint. Without it a
// test that refuses everything would look identical to one that works.
func TestTheHonestCheckpointIsStillAccepted(t *testing.T) {
	dir := servedWithCheckpoint(t, filepath.Join(vectors(), "served", "checkpoint"))
	out, err := exec.Command(nornBinary(t), "verify",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("the honest checkpoint was refused: %v\n%s", err, out)
	}
}
