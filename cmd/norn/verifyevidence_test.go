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
