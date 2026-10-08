package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/trust"
)

// The command a sceptical reader runs. It reaches nothing and trusts nobody:
// a trust file they already had, a file they were sent, and an answer.

// forkedPair builds two conflicting cosigned heads for the fixture's network.
func forkedPair(t *testing.T, anchor *trust.Trust) *forkevidence.Evidence {
	t.Helper()
	mine := treeOver(t, "mine-", 20)
	theirs := treeOver(t, "theirs-", 10)

	mineSigned := signAndCosign(t, anchor, mine)
	theirsSigned := signAndCosign(t, anchor, theirs)
	head, err := tlog.Verify(theirsSigned, []string{anchor.LogKey})
	if err != nil {
		t.Fatal(err)
	}

	evidence, err := forkevidence.Build(mine, mineSigned, theirsSigned, head)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Policy = anchor.Policy
	return evidence
}

func treeOver(t *testing.T, prefix string, n int) *tlog.Tree {
	t.Helper()
	var entries [][]byte
	for i := 0; i < n; i++ {
		entries = append(entries, []byte(prefix+string(rune('a'+i))))
	}
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func signAndCosign(t *testing.T, anchor *trust.Trust, tree *tlog.Tree) string {
	t.Helper()
	signed, err := tree.Checkpoint(anchor.Origin).Sign(fixtureKey(t, "logkey"))
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := note.Split(signed)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pi", "vps"} {
		line, err := cosign.Sign(body, "norn-witness/"+name, fixtureKey(t, "witness-"+name),
			time.Unix(1_760_003_600, 0))
		if err != nil {
			t.Fatal(err)
		}
		signed += line + "\n"
	}
	return signed
}

func TestVerifyEvidenceProvesAForkOffline(t *testing.T) {
	bin := nornBinary(t)
	trustFile := filepath.Join(vectors(), "trust.cbor")
	anchor := readAnchor(t, trustFile)

	raw, err := forkedPair(t, anchor).Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "1760000000.evidence")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	out, stderr, err := run(t, bin, "verify-evidence", "-trust", trustFile, path)
	if err != nil {
		t.Fatalf("verify-evidence: %v\n%s", err, stderr)
	}
	if !strings.Contains(out, "FORK PROVEN") {
		t.Errorf("the verdict should be unmistakable:\n%s", out)
	}
	// It has to say *where*, or a reader cannot check it against anything.
	if !strings.Contains(out, "at size     10") {
		t.Errorf("the size the log equivocated at should be on screen:\n%s", out)
	}
	// And name the witnesses who cosigned both, since they are who a reader
	// goes to next.
	if !strings.Contains(out, "pi") {
		t.Errorf("the witnesses meant to prevent this should be named:\n%s", out)
	}
}

// A file that does not prove a fork must be reported as such. For a reader
// checking somebody else's accusation, that is the important direction.
func TestVerifyEvidenceRefusesAFileThatProvesNothing(t *testing.T) {
	bin := nornBinary(t)
	trustFile := filepath.Join(vectors(), "trust.cbor")
	anchor := readAnchor(t, trustFile)

	evidence := forkedPair(t, anchor)
	// The same head twice is not a fork.
	evidence.Conflicting = evidence.Held
	raw, err := evidence.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bogus.evidence")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := run(t, bin, "verify-evidence", "-trust", trustFile, path)
	if err == nil {
		t.Fatal("a file proving nothing was reported as a fork")
	}
	if !strings.Contains(stderr, "does not prove a fork") {
		t.Errorf("the reason should be plain:\n%s", stderr)
	}
}

// Evidence for another network is not evidence against this one.
func TestVerifyEvidenceRefusesAnotherNetworksFork(t *testing.T) {
	bin := nornBinary(t)
	trustFile := filepath.Join(vectors(), "trust.cbor")
	anchor := readAnchor(t, trustFile)

	other := *anchor
	other.Origin = "norn/somebody-elses-network"
	evidence := forkedPair(t, anchor)
	raw, err := evidence.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "other.evidence")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// A trust file for a different origin must not accept it.
	otherTrust := filepath.Join(t.TempDir(), "other.trust")
	encoded, err := other.Encode()
	if err != nil {
		t.Skipf("cannot build a second anchor: %v", err)
	}
	if err := os.WriteFile(otherTrust, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, bin, "verify-evidence", "-trust", otherTrust, path); err == nil {
		t.Fatal("evidence was accepted against another network's anchor")
	}
}

// pairUnder is forkedPair signed by the named log key and cosigned by the
// named witnesses.
func pairUnder(t *testing.T, anchor *trust.Trust, key string, witnesses ...string) *forkevidence.Evidence {
	t.Helper()
	sign := func(tree *tlog.Tree) string {
		signed, err := tree.Checkpoint(anchor.Origin).Sign(fixtureKey(t, key))
		if err != nil {
			t.Fatal(err)
		}
		body, _, err := note.Split(signed)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range witnesses {
			line, err := cosign.Sign(body, "norn-witness/"+name, fixtureKey(t, "witness-"+name),
				time.Unix(1_760_003_600, 0))
			if err != nil {
				t.Fatal(err)
			}
			signed += line + "\n"
		}
		return signed
	}
	mine, theirs := treeOver(t, "mine-", 20), treeOver(t, "theirs-", 10)
	theirsSigned := sign(theirs)
	cp, err := tlog.ParseCheckpoint(strings.SplitN(theirsSigned, "\n\n", 2)[0] + "\n")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := forkevidence.Build(mine, sign(mine), theirsSigned, cp)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Policy = anchor.Policy
	return evidence
}

func writeEvidenceFile(t *testing.T, ev *forkevidence.Evidence) string {
	t.Helper()
	raw, err := ev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "1760000000.evidence")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// rotatedLog is served/ under the head signed by the first log key its roots
// published, as served-rotated/cases.json says to serve it.
func rotatedLog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join(vectors(), "served"))); err != nil {
		t.Fatal(err)
	}
	head, err := os.ReadFile(filepath.Join(vectors(), "served-rotated", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), head, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// SEC-005 (b), for the stranger's command (row 005bc-ii). A reader with only
// the trust file cannot know a key the roots published after it was issued,
// and refuses evidence signed by it -- correctly, and the command says so. A
// reader who points it at the network's log learns that key the way a node
// does: replayed from the pinned genesis, root-signed, under a head that
// verifies. Then the same file proves the fork.
func TestVerifyEvidenceLearnsARotatedLogKeyFromTheLog(t *testing.T) {
	bin := nornBinary(t)
	trustFile := filepath.Join(vectors(), "trust.cbor")
	path := writeEvidenceFile(t, pairUnder(t, readAnchor(t, trustFile), "logkey2", "pi", "vps", "friend"))

	if _, stderr, err := run(t, bin, "verify-evidence", "-trust", trustFile, path); err == nil ||
		!strings.Contains(stderr, "does not prove a fork") {
		t.Fatalf("a key the trust file never named was accepted without the log: %v\n%s", err, stderr)
	}
	out, stderr, err := run(t, bin, "verify-evidence", "-trust", trustFile, "-log", rotatedLog(t), path)
	if err != nil || !strings.Contains(out, "FORK PROVEN") {
		t.Fatalf("with the log, the published key should prove the fork: %v\n%s%s", err, out, stderr)
	}
	if !strings.Contains(out, "published") {
		t.Errorf("the verdict should say it used what the network published:\n%s", out)
	}
}

// SEC-005 (c). The roots raised the quorum to three of three in the log. A
// file two witnesses cosigned proves a fork to a reader holding only the
// trust file's two of three -- that is what the trust file says -- and not to
// a reader who has read the raise.
func TestVerifyEvidenceFromTheLogAppliesTheRaisedQuorum(t *testing.T) {
	bin := nornBinary(t)
	trustFile := filepath.Join(vectors(), "trust.cbor")
	path := writeEvidenceFile(t, pairUnder(t, readAnchor(t, trustFile), "logkey", "pi", "vps"))

	if out, stderr, err := run(t, bin, "verify-evidence", "-trust", trustFile, path); err != nil ||
		!strings.Contains(out, "FORK PROVEN") {
		t.Fatalf("under the trust file's two of three this file proves a fork: %v\n%s", err, stderr)
	}
	_, stderr, err := run(t, bin, "verify-evidence", "-trust", trustFile,
		"-log", filepath.Join(vectors(), "served"), path)
	if err == nil || !strings.Contains(stderr, "does not prove a fork") {
		t.Fatalf("two witnesses proved a fork to a reader who read the raise to three: %v\n%s", err, stderr)
	}
}
