package logclient

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
)

// Cold gate run 13, D4 and D18. Four refusals §10.1 states that no file
// reached, so a reader could skip each and pass: step 3 before step 4 (a
// checkpoint whose body is wrong AND whose signature is untrusted is
// `log-signature`), §6's padded root (`checkpoint`), and step 1's `unserved`
// for the checkpoint itself and for a hash tile step 11 needs. The
// data-driven tests check each code; this checks each case exists and really
// carries the faults it claims, or it pins nothing.
func TestTheServedPathsUnreachedRefusalsAreVectored(t *testing.T) {
	var checkpoints struct {
		Codes map[string]refusal.Code `json:"codes"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", "cases.json"))), &checkpoints); err != nil {
		t.Fatal(err)
	}
	anchor := shippedLogAnchor(t)
	body := func(t *testing.T, name string) (signed string, lines []string) {
		t.Helper()
		signed = readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", name+".checkpoint"))
		text, _, err := note.Split(signed)
		if err != nil {
			t.Fatalf("%s does not split, so step 2 decides it: %v", name, err)
		}
		return signed, strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	}

	t.Run("step 3 before step 4", func(t *testing.T) {
		const name = "30-noncanonical-size-under-untrusted-signer"
		if got := checkpoints.Codes[name]; got != refusal.LogSignature {
			t.Fatalf("checkpoints-bad/%s is coded %q, want %q", name, got, refusal.LogSignature)
		}
		signed, lines := body(t, name)
		if n, err := strconv.ParseUint(lines[1], 10, 64); err == nil && strconv.FormatUint(n, 10) == lines[1] {
			t.Errorf("size line %q is canonical, so step 4 would not fire and the order is not pinned", lines[1])
		}
		if _, err := note.Verify(signed, anchor.LogKeys); err == nil {
			t.Error("it verifies under the anchored log key, so step 3 would not fire")
		}
	})

	t.Run("an unpadded root", func(t *testing.T) {
		const name = "29-root-unpadded"
		if got := checkpoints.Codes[name]; got != refusal.Checkpoint {
			t.Fatalf("checkpoints-bad/%s is coded %q, want %q", name, got, refusal.Checkpoint)
		}
		signed, lines := body(t, name)
		root := lines[2]
		decoded, err := base64.RawStdEncoding.DecodeString(root)
		if strings.HasSuffix(root, "=") || err != nil || len(decoded) != 32 {
			t.Errorf("root %q is not the 32-byte root with its padding dropped", root)
		}
		if _, err := note.Verify(signed, anchor.LogKeys); err != nil {
			t.Errorf("not signed by the log key over its own text (%v), so step 3 decides it", err)
		}
	})

	cases, codes, _ := servedNegatives(t)
	removes := func(match func(path string) bool) (string, bool) {
		for _, c := range cases {
			if c.Remove && match(c.Path) {
				return c.Name, true
			}
		}
		return "", false
	}
	for _, want := range []struct {
		what  string
		match func(string) bool
	}{
		{"the checkpoint", func(p string) bool { return p == "checkpoint" }},
		{"a hash tile", func(p string) bool {
			return strings.HasPrefix(p, "tile/") && !strings.HasPrefix(p, "tile/entries/")
		}},
	} {
		t.Run("missing "+want.what, func(t *testing.T) {
			name, ok := removes(want.match)
			if !ok {
				t.Fatalf("no served-bad case removes %s", want.what)
			}
			if codes[name] != refusal.Unserved {
				t.Errorf("served-bad/%s is coded %q, want %q", name, codes[name], refusal.Unserved)
			}
		})
	}
}
