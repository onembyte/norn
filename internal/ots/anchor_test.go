package ots

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// What a node checks about an anchor, and what it refuses to claim.
//
// D-009 makes this advisory: it defeats backdating under full log-plus-witness
// collusion and nothing else. So every answer here is evidence for a person to
// read, and none of it can make a peer proven.

func checkpointBody(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	body, _, _ := strings.Cut(string(raw), "\n\n")
	return body + "\n\n"
}

func checkpointProof(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"anchors", checkpointProofName(t)))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The path from a checkpoint to what an anchor says about it.
func TestAnAnchorIsCheckedAgainstTheCheckpointBody(t *testing.T) {
	report, err := CheckAnchor(checkpointProof(t), checkpointBody(t))
	if err != nil {
		t.Fatalf("the fixture's anchor does not check out: %v", err)
	}

	if !report.Chains {
		t.Error("the proof should chain from this checkpoint")
	}
	if report.Earliest == nil {
		t.Fatal("a confirmed attestation should give an earliest-existence claim")
	}
	if report.Earliest.Height != 800000 {
		t.Errorf("height = %d", report.Earliest.Height)
	}
	if report.Pending != 1 {
		t.Errorf("pending = %d, want the one waiting at a calendar", report.Pending)
	}
}

// The property the whole thing is for: a checkpoint edited after stamping has
// an anchor that no longer chains, and this is visible with no network.
func TestAnEditedCheckpointBreaksItsAnchor(t *testing.T) {
	// Bump whatever size the body claims, rather than a literal: a fixture
	// that grows turns a hardcoded edit into no edit at all, and the test
	// would then pass by comparing the checkpoint with itself.
	body := checkpointBody(t)
	lines := strings.Split(body, "\n")
	size, err := strconv.Atoi(lines[1])
	if err != nil {
		t.Fatalf("the checkpoint's size line is %q: %v", lines[1], err)
	}
	lines[1] = strconv.Itoa(size + 1)
	edited := strings.Join(lines, "\n")
	if edited == body {
		t.Fatal("the edit changed nothing")
	}

	_, err = CheckAnchor(checkpointProof(t), edited)
	if err == nil {
		t.Fatal("an anchor was accepted for a checkpoint it was not made over")
	}
	if !strings.Contains(err.Error(), "different document") {
		t.Errorf("the error should say the proof is for other bytes: %v", err)
	}
}

// A proof with nothing but pending attestations proves nothing yet, and must
// say so rather than being reported as an anchor.
func TestAPendingOnlyProofIsNotYetEvidence(t *testing.T) {
	report, err := Report(pendingOnly(t), checkpointBody(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.Earliest != nil {
		t.Error("a calendar's promise was reported as a confirmed anchor")
	}
	if report.Pending == 0 {
		t.Error("the pending branch should still be reported; it is why to look again")
	}
	if !strings.Contains(report.Summary(), "not yet") {
		t.Errorf("the summary should be plain about it: %q", report.Summary())
	}
}

// The summary is what an operator reads, so it must never sound like proof of
// something this tool checked. Confirming a commitment is in a block needs a
// chain, and Norn has not got one.
func TestTheSummaryDoesNotOverclaim(t *testing.T) {
	report, err := CheckAnchor(checkpointProof(t), checkpointBody(t))
	if err != nil {
		t.Fatal(err)
	}
	summary := report.Summary()
	if !strings.Contains(summary, "800000") {
		t.Errorf("the block should be named: %q", summary)
	}
	for _, overclaim := range []string{"confirmed on", "proven at", "verified in"} {
		if strings.Contains(summary, overclaim) {
			t.Errorf("%q claims something no Bitcoin node checked: %q", overclaim, summary)
		}
	}
	if !strings.Contains(summary, "not checked here") {
		t.Errorf("the summary must say what was not checked: %q", summary)
	}
}

// pendingOnly is the fixture's proof with its confirmed branch removed, which
// is what a freshly stamped checkpoint looks like before Bitcoin catches up.
//
// It prunes the parsed tree rather than writing new bytes: this package has no
// serializer on purpose. Norn reads `.ots` files and never writes them, and a
// writer built only to make a test fixture would be exactly the self-agreement
// the vector exists to avoid.
func pendingOnly(t *testing.T) *Proof {
	t.Helper()
	parsed, err := Parse(checkpointProof(t))
	if err != nil {
		t.Fatal(err)
	}
	var kept []Step
	for _, step := range parsed.Tree.Steps {
		if step.Op.Name == "prepend" {
			kept = append(kept, step)
		}
	}
	if len(kept) != 1 {
		t.Fatalf("expected one pending branch, found %d", len(kept))
	}
	parsed.Tree.Steps = kept
	return parsed
}

// The fixture's proof is named for the tree size (SPEC §6), so it is found
// rather than spelled -- the fixture gained four entries in 6.5d-ii and every
// hardcoded name went stale together.
func checkpointProofName(t *testing.T) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors",
		"anchors", "checkpoint-*.ots"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("want exactly one checkpoint proof, found %v (%v)", matches, err)
	}
	return filepath.Base(matches[0])
}
