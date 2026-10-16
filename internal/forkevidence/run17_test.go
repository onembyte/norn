package forkevidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/replay"
)

func TestRunSeventeenEvidenceRefusalsHaveSoundTwins(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	anchor := shippedAnchor(t, root)
	read := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var manifest struct{ Codes map[string]string }
	if err := json.Unmarshal(read(t, "fork/cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, code string }{
		{"bad-split-zero-with-a-root", "proof"}, {"bad-declared-length-past-the-file", "cbor"}, {"bad-empty-map-key", "cbor"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if manifest.Codes[c.name] != c.code {
				t.Error("manifest must name " + c.code)
			}
			sound := read(t, "fork/evidence.cbor")
			ev, err := Parse(sound)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy); err != nil {
				t.Fatal(err)
			}
			raw := read(t, "fork/"+c.name+".cbor")
			bad, err := Parse(raw)
			if err == nil {
				_, err = Check(bad, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
			}
			code, _ := evrefusal.CodeOf(err)
			if string(code) != c.code {
				t.Fatalf("Go answers %q (%v), SPEC states %s", code, err, c.code)
			}
			switch c.name {
			case "bad-split-zero-with-a-root":
				if bad.Split != 0 || len(bad.SplitProofHeld)+len(bad.SplitProofConflicting) != 0 || bytes.Equal(bad.SplitRoot, make([]byte, 32)) {
					t.Fatal("need split 0, nonzero root and empty proofs")
				}
				bad.SplitRoot = make([]byte, 32)
				if _, err := Check(bad, anchor.Origin, []string{anchor.LogKey}, anchor.Policy); err != nil {
					t.Fatal(err)
				}
			case "bad-declared-length-past-the-file":
				if len(raw) > 11 || !bytes.HasPrefix(raw, []byte{0x7a, 0, 1, 0x11, 0x70}) {
					t.Fatal("need a short file declaring 70000 text bytes")
				}
			case "bad-empty-map-key":
				// The empty key sorts first. Removing just that pair restores the twin.
				fixed := append([]byte{raw[0] - 1}, raw[3:]...)
				if !bytes.Equal(fixed, sound) {
					t.Fatal("empty pair must be the only change")
				}
			}
			t.Logf("fork/%s: %s; sound twin: accept", c.name, code)
		})
	}
}

func TestRunSeventeenEvidenceUsesTheReadersReplayedPolicy(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	doc := shippedAnchor(t, root)
	raw, err := os.ReadFile(filepath.Join(root, "replayed-policy", "evidence.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(ev, doc.Origin, []string{doc.LogKey}, doc.Policy); err != nil {
		t.Fatal(err)
	}
	result, err := logclient.Verify(logclient.Dir(filepath.Join(root, "served")), logclient.Anchor{Anchor: replay.FromTrust(doc), Origin: doc.Origin, LogKeys: []string{doc.LogKey}, Policy: doc.Policy})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Check(ev, doc.Origin, []string{doc.LogKey}, logclient.PolicyFrom(result.State))
	if code, _ := evrefusal.CodeOf(err); code != evrefusal.Held {
		t.Fatalf("Go answers %q (%v), SPEC states held", code, err)
	}
	soundRaw, err := os.ReadFile(filepath.Join(root, "fork", "evidence.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	sound, err := Parse(soundRaw)
	if err != nil {
		t.Fatal(err)
	}
	stripped := func(head string) string {
		var lines []string
		for _, line := range strings.Split(head, "\n") {
			if !strings.HasPrefix(line, "— norn-witness/friend ") {
				lines = append(lines, line)
			}
		}
		return strings.Join(lines, "\n")
	}
	if ev.Held != stripped(sound.Held) || ev.Conflicting != stripped(sound.Conflicting) {
		t.Fatal("only friend's two lines may be removed")
	}
	ev.Held, ev.Conflicting = sound.Held, sound.Conflicting
	restored, err := ev.Encode()
	if err != nil || !bytes.Equal(restored, soundRaw) {
		t.Fatal("restoring friend must recover sound evidence byte for byte")
	}
	if _, err := Check(sound, doc.Origin, []string{doc.LogKey}, logclient.PolicyFrom(result.State)); err != nil {
		t.Fatal(err)
	}
}
