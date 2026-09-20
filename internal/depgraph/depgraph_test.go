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

// A verifier reads cosignatures off the checkpoint it fetched; it never talks
// to a witness. The distinction is the whole shape of `GOSSIP.md` part 1:
// witnesses guard the *log*, and a node checks their signatures offline. A
// verifier that dialled a witness would put a network round trip -- and a
// third party's availability -- on the path that decides whether a peer stays
// in the table.
func TestTheVerifierNeverTalksToAWitness(t *testing.T) {
	for _, pkg := range []string{
		"github.com/onembyte/norn/internal/logclient",
		"github.com/onembyte/norn/internal/agent",
		"github.com/onembyte/norn/cmd/nornd",
	} {
		forbid(t, pkg, []string{"github.com/onembyte/norn/internal/witness"},
			"Witnesses are asked by the log, not by the nodes reading it.")
	}
}

// And the witness client is log-side: it has no business knowing how a peer
// table is driven.
func TestTheWitnessClientDoesNotCarryAKernelDriver(t *testing.T) {
	forbid(t, "github.com/onembyte/norn/internal/witness", kernelDriver,
		"Submitting a checkpoint is an HTTP request, not an interface operation.")
}

// Gossip is a file server and a fetcher, and nothing else.
//
// It depends on **no other Norn package at all** -- not the verifier, not the
// enforcement side. That is not tidiness: it is the design claim made
// structural. A peer serves bytes and the receiver verifies them with the same
// code it uses on the log, so there is nothing for a gossip-specific trust
// model to live in. `Peer` satisfies `logclient.Fetcher` without importing it,
// because Go interfaces are structural; the day this package needs to import
// the verifier is the day gossip has grown an opinion about what to believe.
func TestGossipKnowsNothingAboutVerifying(t *testing.T) {
	imported := deps(t, "github.com/onembyte/norn/internal/gossip")
	for dep := range imported {
		if strings.HasPrefix(dep, "github.com/onembyte/norn/") &&
			dep != "github.com/onembyte/norn/internal/gossip" {
			t.Errorf("internal/gossip depends on %s.\nA peer serves bytes; whoever "+
				"reads them decides what they mean.", dep)
		}
	}
}

// D-009 makes OpenTimestamps anchoring an **advisory** witness type that
// "never touches the handshake path". That is a claim about what can influence
// whether a peer is proven, so it is enforced here rather than remembered: the
// verifier, the agent and the daemon may not import the proof reader at all.
//
// Anchoring answers "was this checkpoint backdated", which is a question for
// an operator looking at evidence -- not for the code deciding what goes in
// the peer table in the next 200 milliseconds.
func TestAnchoringNeverTouchesTheHandshakePath(t *testing.T) {
	for _, pkg := range []string{
		"github.com/onembyte/norn/internal/logclient",
		"github.com/onembyte/norn/internal/agent",
		"github.com/onembyte/norn/cmd/nornd",
	} {
		forbid(t, pkg, []string{"github.com/onembyte/norn/internal/ots"},
			"Anchoring is advisory (D-009) and must not be able to decide anything.")
	}
}
