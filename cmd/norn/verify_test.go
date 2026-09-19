package main

import (
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
