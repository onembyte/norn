package logclient

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/refusal"
)

// Only served cases reach this walker. The size-at-cap body belongs to the
// checkpoint layer and must never be used to request that many entries.
func TestEveryPositiveServedCheckpointAcceptsAtItsInclusiveBound(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "checkpoints-good")
	var m struct {
		Cases []struct {
			Name, File, Layer string
			ServeOver         string `json:"serve_over"`
		}
		Codes map[string]string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Cases) != 2 || len(m.Codes) != 2 {
		t.Fatal("need both positive layers")
	}
	seen := map[string]bool{}
	for _, c := range m.Cases {
		if seen[c.Name] || m.Codes[c.Name] != "accept" || c.File != c.Name+".checkpoint" {
			t.Fatal("invalid positive case or code")
		}
		seen[c.Name] = true
		if c.Layer == "checkpoint" {
			if c.Name != "size-at-the-cap" || c.ServeOver != "" {
				t.Fatal("only size-at-the-cap is checkpoint-only")
			}
			continue
		}
		if c.Name != "cosignature-time-at-the-cap" || c.Layer != "served" || c.ServeOver != "../served" {
			t.Fatal("unexpected served positive")
		}
		t.Run(c.Name, func(t *testing.T) {
			signed := readFile(t, filepath.Join(dir, c.File))
			honestDir := filepath.Join(dir, c.ServeOver)
			honest := readFile(t, filepath.Join(honestDir, "checkpoint"))
			if !strings.HasPrefix(signed, honest) {
				t.Fatal("positive must retain the entire served head")
			}
			body, sigs, err := note.Split(signed)
			if err != nil {
				t.Fatal(err)
			}
			_, original, err := note.Split(honest)
			if err != nil {
				t.Fatal(err)
			}
			if len(sigs) != len(original)+1 {
				t.Fatal("only one cosignature may be added")
			}
			last := sigs[len(sigs)-1]
			if last.Name != "norn-witness/pi" || !last.IsCosignature() || binary.BigEndian.Uint64(last.Sig[:8]) != 1<<63-1 {
				t.Fatal("extra pi line must be exactly at the cap")
			}
			anchor := shippedLogAnchor(t)
			result, err := Verify(Dir(servedWith(t, honestDir, signed)), anchor)
			if err != nil {
				t.Fatalf("positive served checkpoint: %v", err)
			}
			if result.Checkpoint.Size != 162 || len(result.Served) != 162 || len(result.Cosignatures) != 4 {
				t.Fatal("served positive lost its ordinary tree or cosignatures")
			}
			found := 0
			for _, sig := range result.Cosignatures {
				if sig.Name == "norn-witness/pi" && sig.Time.Unix() == 1<<63-1 {
					found++
				}
			}
			if found != 1 {
				t.Fatal("verified cosignatures must retain the exact cap")
			}
			// Removing only the extra line returns the ordinary accepted head.
			runFourteenAnswer(t, honestDir, anchor, "accept")
			if body != result.Checkpoint.Marshal() {
				t.Fatal("the signed tree changed")
			}
			t.Log("served head plus pi at 9223372036854775807: accept; extra-line removal: accept")
		})
	}
	if !seen["size-at-the-cap"] || !seen["cosignature-time-at-the-cap"] {
		t.Fatal("missing positive layer")
	}
}

// Check the raw signatures without asking the note parser to accept malformed
// text. A valid block projected onto honest text exposes those exact frames.
func checkSignedTextNotUTF8Checkpoint(t *testing.T) {
	anchor := shippedLogAnchor(t)
	dir := filepath.Join(vectorRoot(), "checkpoints-bad")
	var m struct {
		Cases []string
		Codes map[string]string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &m); err != nil {
		t.Fatal(err)
	}
	const name = "47-signed-text-not-utf8"
	count := 0
	for _, n := range m.Cases {
		if n == name {
			count++
		}
	}
	if count != 1 || m.Codes[name] != "note" {
		t.Fatal("missing signed-text UTF-8 case and note code")
	}
	signed := readFile(t, filepath.Join(dir, name+".checkpoint"))
	honestDir := filepath.Join(vectorRoot(), "served")
	honest := readFile(t, filepath.Join(honestDir, "checkpoint"))
	body, _, err := note.Split(honest)
	if err != nil {
		t.Fatal(err)
	}
	text, block, ok := strings.Cut(signed, "\n\n")
	want := []byte(body)
	want[strings.IndexByte(body, '\n')-1] = 0xff
	if !ok || text+"\n" != string(want) {
		t.Fatal("only one signed origin byte may be invalid UTF-8")
	}
	_, sigs, err := note.Split(body + "\n" + block)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		t.Fatal(err)
	}
	keys := append(append([]string(nil), anchor.LogKeys...), rules.Keys()...)
	if len(sigs) != 4 {
		t.Fatal("need the log and all three witnesses")
	}
	seen := map[string]bool{}
	for _, sig := range sigs {
		matched := false
		for _, raw := range keys {
			key, err := note.ParseVerifierKey(raw)
			if err != nil {
				t.Fatal(err)
			}
			if sig.Name != key.Name || string(sig.KeyID) != string(key.ID()) {
				continue
			}
			msg, signature := []byte(text+"\n"), sig.Sig
			if key.IsCosigner() {
				if !sig.IsCosignature() {
					t.Fatal("wrong witness length")
				}
				at := time.Unix(int64(binary.BigEndian.Uint64(sig.Sig[:8])), 0)
				msg, signature = cosign.Message(at, text+"\n"), sig.Sig[8:]
			}
			if !ed25519.Verify(key.Public, msg, signature) {
				t.Fatal("exact malformed text was not signed")
			}
			if seen[key.Name] {
				t.Fatal("repeated signer")
			}
			seen[key.Name], matched = true, true
			break
		}
		if !matched {
			t.Fatal("signature must name a trusted key")
		}
	}
	_, err = Verify(Dir(servedWith(t, honestDir, signed)), anchor)
	if code, _ := refusal.CodeOf(err); code != refusal.Note {
		t.Fatalf("signed-text refusal = %q (%v), want note", code, err)
	}
	runFourteenAnswer(t, honestDir, anchor, "accept")
	t.Log("exact malformed text signed by log and all three witnesses: note; honest signed head: accept")
}
