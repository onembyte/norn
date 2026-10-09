package docclaims

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// HC. Every CI run warned that actions/checkout@v4, setup-go@v5 and
// setup-python@v5 target Node 20, which GitHub now forces onto Node 24. The
// workflow is a claim about what runs, and nothing checked it: a step copied
// from an old snippet would bring Node 20 back without a sound. The minimums
// are each action's first Node 24 major, read from its action.yml (`runs:
// using: node24`) on 2026-10-08.
//
// The row also fixes the trigger: until the owner lifts the Actions-budget
// rule (2026-11-01) a job runs on push or by hand, never on a `schedule:`.
func TestTheCIWorkflowRunsSupportedActionsAndNoSchedule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	// H7-f keeps the simulator visible as its own Linux job, rather than
	// relying on the full suite to happen to run its scenarios.
	job := regexp.MustCompile(`(?m)^  lab-sim:\n(?:^    .*\n|^\n)*`).FindString(string(raw))
	if job == "" {
		t.Error("ci.yml must have a lab-sim job")
	} else {
		if !regexp.MustCompile(`(?m)^    runs-on: ubuntu-latest$`).MatchString(job) {
			t.Error("the lab-sim job must run on ubuntu-latest")
		}
		if !regexp.MustCompile(`(?m)^      - run: make lab-sim$`).MatchString(job) {
			t.Error("the lab-sim job must call make lab-sim")
		}
	}
	// govulncheck runs only by hand: it is the one job the row names, and a
	// vulnerability scan on every push would spend what the budget rule saves.
	vuln, err := os.ReadFile(filepath.Join(root(t), ".github", "workflows", "govulncheck.yml"))
	if err != nil {
		t.Fatalf("the govulncheck workflow the row names is missing: %v", err)
	}
	if !strings.Contains(string(vuln), "on: [workflow_dispatch]") {
		t.Error("govulncheck.yml must run by hand only (`on: [workflow_dispatch]`)")
	}
	workflow := string(raw) + "\n" + string(vuln)
	firstNode24 := map[string]int{"checkout": 5, "setup-go": 6, "setup-python": 6}
	uses := regexp.MustCompile(`uses:\s*actions/([a-z-]+)@v(\d+)`)
	seen := map[string]bool{}
	for _, m := range uses.FindAllStringSubmatch(workflow, -1) {
		name, major := m[1], m[2]
		minimum, known := firstNode24[name]
		if !known {
			t.Errorf("actions/%s is not one this test knows the Node 24 major of: add it", name)
			continue
		}
		seen[name] = true
		if n, _ := strconv.Atoi(major); n < minimum {
			t.Errorf("actions/%s@v%s targets Node 20; v%d is its first Node 24 major", name, major, minimum)
		}
	}
	for name := range firstNode24 {
		if !seen[name] {
			t.Errorf("the workflow no longer uses actions/%s; this test is out of date", name)
		}
	}
	for _, line := range strings.Split(workflow, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "schedule:") {
			t.Errorf("a `schedule:` trigger, which the Actions-budget rule forbids until 2026-11-01: %q", line)
		}
	}
}

// H7-f runs the simulator, not the lab's wall-clock scripts. Its result
// directory must be supplied explicitly so T7 can write its measurements.
func TestTheMakefileRunsTheSimulatorWithAResultDirectory(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	target := regexp.MustCompile(`(?m)^lab-sim:[^\n]*\n(?:^\t.*\n)*`).FindString(string(raw))
	if target == "" {
		t.Fatal("Makefile must have a lab-sim target")
	}
	for _, name := range []string{"./internal/sim", "NORN_SIM_RESULTS"} {
		if !strings.Contains(target, name) {
			t.Errorf("the lab-sim recipe must name %s", name)
		}
	}
}

// HC-c (audit SEC-017). `go.mod`'s `go` line is the oldest Go that may build
// the module, and with no `toolchain` line it is also what CI builds with:
// setup-go installed exactly `go1.26.0`, and govulncheck found 35 reachable
// standard-library vulnerabilities in it, every one fixed in a later patch.
// The `toolchain` line names the release CI builds and tests with. Only its
// presence needs checking here: the go command itself refuses a `toolchain`
// no newer than the `go` line ("updates to go.mod needed").
func TestGoModNamesAPatchedToolchain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^toolchain go\d+\.\d+\.\d+\s*$`).Match(raw) {
		t.Error("go.mod names no `toolchain`: CI builds with the `go` line's release, which govulncheck found vulnerable")
	}
}
