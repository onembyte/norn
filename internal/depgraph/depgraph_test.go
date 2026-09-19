// Package depgraph holds architecture tests: facts about which package may
// depend on which, enforced rather than described.
package depgraph

import (
	"os/exec"
	"strings"
	"testing"
)

// deps returns everything a package transitively imports.
func deps(t *testing.T, pkg string) map[string]bool {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" {
			set[line] = true
		}
	}
	return set
}

func forbid(t *testing.T, pkg string, forbidden []string, why string) {
	t.Helper()
	imported := deps(t, pkg)
	for _, bad := range forbidden {
		for dep := range imported {
			if strings.HasPrefix(dep, bad) {
				t.Errorf("%s depends on %s.\n%s", pkg, dep, why)
				break
			}
		}
	}
}

// wgctrl is 18 modules, including gvisor and wintun, and it is the price of
// driving a kernel (D-059). It is worth paying once, in the daemon that has to
// drive one — and nowhere else.
var kernelDriver = []string{
	"golang.zx2c4.com/wireguard",
	"github.com/onembyte/norn/internal/wgdev",
}

// `norn` is the operator's CLI: it verifies logs, signs entries and reads
// state. It never touches an interface, so it must never carry the cost of
// being able to.
func TestTheCLIDoesNotCarryAKernelDriver(t *testing.T) {
	forbid(t, "github.com/onembyte/norn/cmd/norn", kernelDriver,
		"The CLI runs on laptops and in CI; it has no interface to drive.")
}

// `norn-log` serves files and accepts submissions. It is the least trusted
// component here and should be the smallest.
func TestTheLogServerDoesNotCarryAKernelDriver(t *testing.T) {
	forbid(t, "github.com/onembyte/norn/cmd/norn-log", kernelDriver,
		"A log serves files; it has no business linking a WireGuard driver.")
}

// The enforcement logic must stay testable without a kernel. This is what
// makes every attack case in internal/reconcile a unit test rather than a lab
// run, and it holds only while nothing above the seam knows what a real
// interface is.
func TestTheEnforcementLogicDoesNotKnowAboutKernels(t *testing.T) {
	for _, pkg := range []string{
		"github.com/onembyte/norn/internal/reconcile",
		"github.com/onembyte/norn/internal/agent",
		"github.com/onembyte/norn/internal/peertable",
		"github.com/onembyte/norn/internal/endpoint",
	} {
		forbid(t, pkg, kernelDriver,
			"Enforcement decisions are tested against peertable.Device, not a kernel.")
	}
}

// The verifier is the part a second implementation has to reproduce. It stays
// stdlib-plus-transparency-formats, and nothing about WireGuard belongs in it.
func TestTheVerifierStaysNarrow(t *testing.T) {
	forbid(t, "github.com/onembyte/norn/internal/logclient",
		append([]string{"github.com/BurntSushi"}, kernelDriver...),
		"A verifier needs a log and a trust anchor, and nothing else.")
}
