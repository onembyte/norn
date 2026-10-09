package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/logclient"
)

// VerifyAnchoredReportsTheAnchor already covers the block claim and its
// offline limit, VerifyAnchoredIsAdvisory covers a missing stamp, and
// VerifyAnchoredReportsAMismatchedProof covers an unrelated proof. The
// stamp tests also pin the digest range and a fresh calendar's promise.
// T8 adds an actual one-byte checkpoint edit and compares CLI decisions
// with and without the advisory flag. No calendar or Bitcoin node is asked.
func TestT8AnEditAfterStampingIsUnusableAndAnchoringStaysAdvisory(t *testing.T) {
	bin := nornBinary(t)
	log := anchoredLog(t)
	anchor, err := loadAnchor(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := logclient.Verify(logclient.Dir(log), anchorFor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	compare := func(wantOK bool) string {
		t.Helper()
		args := []string{"verify", "-trust", filepath.Join(vectors(), "trust.cbor"), "-log", log}
		plain, plainErrOut, plainErr := run(t, bin, args...)
		anchored, anchoredErrOut, anchoredErr := run(t, bin, append(args, "-anchored")...)
		if (plainErr == nil) != wantOK || (anchoredErr == nil) != wantOK {
			t.Fatalf("anchoring changed the log's decision (want success %t): plain %v, anchored %v\n%s\n%s", wantOK, plainErr, anchoredErr, plainErrOut, anchoredErrOut)
		}
		if plainErrOut != anchoredErrOut || !strings.HasPrefix(anchored, plain) {
			t.Fatalf("anchoring changed the log's report:\nplain: %s%s\nanchored: %s%s", plain, plainErrOut, anchored, anchoredErrOut)
		}
		return anchored
	}
	// The served vector also carries a Bitcoin claim; that claim is not
	// checked offline. Its pending calendar branch must remain visible.
	if out := compare(true); !strings.Contains(out, "1 branch(es) still pending at a calendar") {
		t.Fatalf("the vector's pending calendar attestation was not reported:\n%s", out)
	}

	original := []byte(result.SignedCheckpoint)
	edited := editT8Checkpoint(original)
	if err := os.WriteFile(filepath.Join(log, "checkpoint"), edited, 0o644); err != nil {
		t.Fatal(err)
	}
	// A body edit invalidates the log signature, so verify correctly refuses
	// before reporting any anchor. Exercise the reporter separately over the
	// edited bytes; this result is never passed to a verifier or a node.
	reportOnly := *result
	reportOnly.SignedCheckpoint = string(edited)
	out := renderedT8Anchor(t, logclient.Dir(log), &reportOnly)
	if !strings.Contains(out, "UNUSABLE") || !strings.Contains(out, "different document") {
		t.Fatalf("an edit after stamping was not reported as UNUSABLE:\n%s", out)
	}
	changed := 0
	for i := range original {
		if original[i] != edited[i] {
			changed++
		}
	}
	if len(edited) != len(original) || changed != 1 {
		t.Fatalf("the checkpoint edit changed %d bytes, want exactly one", changed)
	}
	compare(false)

	// The existing mismatched-proof test checks the warning, but does not
	// assert success. Keep the log valid and attach that proof to close the
	// advisory-success half even when the reporter says UNUSABLE.
	if err := os.WriteFile(filepath.Join(log, "checkpoint"), original, 0o644); err != nil {
		t.Fatal(err)
	}
	sample, err := os.ReadFile(filepath.Join(vectors(), "anchors", "sample.ots"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(log, "anchors", servedSize(t)+".ots"), sample, 0o644); err != nil {
		t.Fatal(err)
	}
	if out := compare(true); !strings.Contains(out, "UNUSABLE") {
		t.Fatalf("the unusable advisory stamp was not reported:\n%s", out)
	}
}

func editT8Checkpoint(raw []byte) []byte {
	edited := bytes.Clone(raw)
	// Change the first base64 root byte. The size and anchor path stay the
	// same, so UNUSABLE must come from the digest comparison.
	root := bytes.IndexByte(edited, '\n') + 1
	root += bytes.IndexByte(edited[root:], '\n') + 1
	if edited[root] == 'A' {
		edited[root] = 'B'
	} else {
		edited[root] = 'A'
	}
	return edited
}

func renderedT8Anchor(t *testing.T, fetcher logclient.Fetcher, result *logclient.Result) string {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "anchor")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	original := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = original }()
	reportAnchor(fetcher, result)
	raw, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
