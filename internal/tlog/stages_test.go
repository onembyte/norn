package tlog

import (
	"encoding/base64"
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

// The checkpoint root is 32 bytes, so its padded base64 has unused low bits
// in the final data character. Those bits must be zero even when the decoded
// root is unchanged.
func TestParseCheckpointRejectsNonzeroRootPadBits(t *testing.T) {
	body, _, err := note.Split(read(t, "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	canonical := lines[2]
	raw, err := base64.StdEncoding.DecodeString(canonical)
	if err != nil {
		t.Fatal(err)
	}
	bad := withNonzeroPadBits(t, canonical)
	decoded, err := base64.StdEncoding.DecodeString(bad)
	if err != nil || string(decoded) != string(raw) {
		t.Fatalf("mutated root does not decode to the same bytes: %v", err)
	}
	lines[2] = bad
	if _, err := ParseCheckpoint(strings.Join(lines, "\n") + "\n"); !errors.Is(err, ErrFormat) {
		t.Errorf("ParseCheckpoint accepted nonzero root pad bits: %v", err)
	}
}

func withNonzeroPadBits(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded {
		t.Fatalf("input is not canonical base64: %v", err)
	}
	padding := len(encoded) - len(strings.TrimRight(encoded, "="))
	if padding == 0 {
		t.Fatal("test input has no padding bits")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	position := len(encoded) - padding - 1
	value := strings.IndexByte(alphabet, encoded[position])
	unused := padding * 2
	mask := (1 << unused) - 1
	mutated := []byte(encoded)
	mutated[position] = alphabet[(value&^mask)|1]
	return string(mutated)
}

// D14b. The terminator on the final signature line is exactly one LF. The
// parser must not trim an extra blank line, and must not accept an unterminated
// final line.
func TestSignatureBlockRequiresExactlyOneFinalLineFeed(t *testing.T) {
	signed := read(t, "served", "checkpoint")
	origin := originOf(signed)
	keys := []string{logVerifierKey(t, origin)}
	for name, input := range map[string]string{
		"missing final LF": strings.TrimSuffix(signed, "\n"),
		"extra final LF":   signed + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(input, keys)
			if code, ok := refusal.CodeOf(err); err == nil || !ok || code != refusal.Note {
				t.Errorf("Verify error = %v (code %q, coded %t), want note framing", err, code, ok)
			}
		})
	}
}

// D14c. A 76-byte payload is a valid framed payload in isolation, but it is
// not a valid signature for the trusted log key (whose algorithm requires 68
// bytes). Since its name and key ID match that key, it is a verification
// failure at step 3, even beside another valid line from that key.
func TestOtherAlgorithmLengthUnderTheTrustedLogKeyIsLogSignature(t *testing.T) {
	signed := read(t, "served", "checkpoint")
	origin := originOf(signed)
	key := logVerifierKey(t, origin)
	v, err := note.ParseVerifierKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// A signature line carries key ID plus an eight-byte timestamp and a
	// 64-byte signature, the other supported payload length.
	payload := append(append([]byte(nil), v.ID()...), make([]byte, 8+64)...)
	line := note.SigPrefix + v.Name + " " + base64.StdEncoding.EncodeToString(payload) + "\n"
	_, err = Verify(signed+line, []string{key})
	if code, ok := refusal.CodeOf(err); err == nil || !ok || code != refusal.LogSignature {
		t.Errorf("Verify error = %v (code %q, coded %t), want log-signature", err, code, ok)
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
