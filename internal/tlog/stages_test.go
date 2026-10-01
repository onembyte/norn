package tlog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
)

// Verify is §10.1's steps 2 to 4: the note's framing, then the log's
// signature, then the checkpoint body. Each refusal carries the code of the
// step that made it (D-061), and everything after step 4 -- the origin, the
// cosignatures, the quorum -- is the caller's, so a checkpoint whose only
// defect lies there has to pass here.
//
// What each file is refused with is cases.json's `codes`, the same list the
// full verifier is held to in internal/logclient. This test used to keep its
// own table of the same answers; one list cannot disagree with itself. A code
// from steps 2-4 is expected here verbatim, and any later step's code means
// these three steps must pass the file.
var stages = map[refusal.Code]bool{refusal.Note: true, refusal.LogSignature: true, refusal.Checkpoint: true}

func TestVerifyNamesTheStageThatRefused(t *testing.T) {
	origin := originOf(read(t, "served", "checkpoint"))
	keys := []string{logVerifierKey(t, origin)}

	var manifest struct {
		Codes map[string]refusal.Code `json:"codes"`
	}
	if err := json.Unmarshal([]byte(read(t, "checkpoints-bad", "cases.json")), &manifest); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(vectorRoot(), "checkpoints-bad", "*.checkpoint"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no checkpoints-bad fixtures: %v", err)
	}
	sort.Strings(files)
	reached := map[refusal.Code]bool{}
	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), ".checkpoint")
		code, classified := manifest.Codes[name]
		if !classified {
			t.Errorf("%s: cases.json names no code for it", name)
			continue
		}
		var want refusal.Code
		if stages[code] {
			want = code
			reached[code] = true
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Verify(string(raw), keys)
		got, coded := refusal.CodeOf(err)
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: refused as %q (%v); it is a `%s` refusal, a later step's, so steps 2-4 must pass it", name, got, err, code)
		case want != "" && err == nil:
			t.Errorf("%s: accepted; cases.json refuses it as %q", name, want)
		case want != "" && (!coded || got != want):
			t.Errorf("%s: refused as %q, want %q (%v)", name, got, want, err)
		}
	}
	// The suite reaches all three of these steps, so none of them can lose its
	// code without a file here noticing.
	for code := range stages {
		if !reached[code] {
			t.Errorf("no checkpoints-bad file is refused as %q", code)
		}
	}
}

// The codes are added to the errors, not substituted for them: whoever tested
// for note.ErrNote or ErrFormat before still finds it.
func TestVerifyKeepsTheErrorsItAlwaysReturned(t *testing.T) {
	origin := originOf(read(t, "served", "checkpoint"))
	keys := []string{logVerifierKey(t, origin)}

	for _, c := range []struct {
		fixture string
		is      error
	}{
		{"01-unsigned", note.ErrNote},
		{"04-forged-log-signature", note.ErrNote},
		{"15-size-leading-zero", ErrFormat},
	} {
		_, err := Verify(read(t, "checkpoints-bad", c.fixture+".checkpoint"), keys)
		if !errors.Is(err, c.is) {
			t.Errorf("%s: %v no longer is %v", c.fixture, err, c.is)
		}
	}
	if _, err := Verify(read(t, "served", "checkpoint"), keys); err != nil {
		t.Fatalf("the honest checkpoint does not verify: %v", err)
	}
}

// A trusted key that does not parse is the caller's configuration, not the
// checkpoint's fault, so it carries no §10.1 code -- and it is reported before
// anything is read from the note, whatever state the note is in.
func TestAMalformedTrustedKeyIsNotARefusalOfTheCheckpoint(t *testing.T) {
	for _, signed := range []string{read(t, "served", "checkpoint"), "not a note"} {
		_, err := Verify(signed, []string{"not a verifier key"})
		if err == nil {
			t.Fatal("a malformed trusted key was accepted")
		}
		if code, ok := refusal.CodeOf(err); ok {
			t.Errorf("a configuration error was reported as the checkpoint's %q", code)
		}
	}
}
