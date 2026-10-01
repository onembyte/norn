package tlog

import (
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
// The expectations are read off §10.1's definitions, not off what this
// package happened to do. Every fixture in checkpoints-bad/ has to appear, so
// a new one cannot land without somebody deciding which step refuses it.
var stageOf = map[string]refusal.Code{
	"01-unsigned":                       refusal.Note, // no signature line at all
	"02-wrong-log-key":                  refusal.LogSignature,
	"03-wrong-origin":                   refusal.LogSignature, // signed as norn/elsewhere: the signature decides before the origin
	"04-forged-log-signature":           refusal.LogSignature,
	"05-one-cosignature-short":          "",
	"06-no-cosignatures":                "",
	"07-unnamed-witness-only":           "",
	"08-forged-cosignature":             "",
	"09-extension-line":                 refusal.Checkpoint,
	"10-wrong-body-origin":              "", // this log's key, this log's name: the origin is step 5
	"11-forged-cosignature-with-quorum": "",
	"12-second-line-from-one-witness":   "",
	"13-ascii-dash-signature":           refusal.Note,
	"14-unterminated-signature-block":   refusal.Note,
	"15-size-leading-zero":              refusal.Checkpoint,
	"16-two-log-signatures":             refusal.LogSignature, // one verifies, one does not
	"17-root-wrong-length":              refusal.Checkpoint,
	"18-signature-name-with-space":      refusal.Note,
	"19-signature-unpadded-base64":      refusal.Note,
	"20-signature-payload-too-long":     refusal.Note,
	"21-origin-with-a-suffix":           "",
	"22-origin-case-changed":            "",
}

func TestVerifyNamesTheStageThatRefused(t *testing.T) {
	origin := originOf(read(t, "served", "checkpoint"))
	keys := []string{logVerifierKey(t, origin)}

	files, err := filepath.Glob(filepath.Join(vectorRoot(), "checkpoints-bad", "*.checkpoint"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no checkpoints-bad fixtures: %v", err)
	}
	sort.Strings(files)
	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), ".checkpoint")
		want, classified := stageOf[name]
		if !classified {
			t.Errorf("%s: not classified; decide which §10.1 step refuses it", name)
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Verify(string(raw), keys)
		got, coded := refusal.CodeOf(err)
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: refused as %q (%v); its defect is a later step's, so steps 2-4 must pass it", name, got, err)
		case want != "" && err == nil:
			t.Errorf("%s: accepted; §10.1 refuses it as %q", name, want)
		case want != "" && (!coded || got != want):
			t.Errorf("%s: refused as %q, want %q (%v)", name, got, want, err)
		}
	}
	for name := range stageOf {
		if _, err := os.Stat(filepath.Join(vectorRoot(), "checkpoints-bad", name+".checkpoint")); err != nil {
			t.Errorf("%s is classified and no longer exists", name)
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
