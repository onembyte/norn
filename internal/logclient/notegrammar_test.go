package logclient

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
)

// Every repair changes only the malformed stranger name or the one witness
// line. The body, honest signatures and served tiles are retained verbatim.
func TestTheNoteGrammarVectorsRefuseTheirFaultAndAcceptItsRepair(t *testing.T) {
	anchor := shippedLogAnchor(t)
	honest := filepath.Join(vectorRoot(), "served")
	base := readFile(t, filepath.Join(honest, "checkpoint"))
	var manifest struct {
		Cases []string
		Codes map[string]string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", "cases.json"))), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, stranger, want string }{
		{"38-cosignature-time-above-2-63", "", "cosignature"},
		{"39-signature-name-empty", "", "note"},
		{"40-signature-name-tab", "stranger\tname", "note"},
		{"41-signature-name-nbsp", "stranger\u00a0name", "note"},
		{"42-signature-name-plus", "stranger+name", "note"},
		{"43-signature-name-nul", "stranger\x00name", "note"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if manifest.Codes[c.name] != c.want {
				t.Fatalf("manifest code %q, want %q", manifest.Codes[c.name], c.want)
			}
			found := false
			for i, name := range manifest.Cases {
				if i > 0 && name <= manifest.Cases[i-1] {
					t.Error("cases must remain in number order")
				}
				if name == c.name {
					found = true
				}
			}
			if !found {
				t.Fatal("vector is absent from cases")
			}
			head := readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", c.name+".checkpoint"))
			_, err := Verify(Dir(servedWith(t, honest, head)), anchor)
			if code, _ := refusal.CodeOf(err); string(code) != c.want {
				t.Fatalf("Go answers %q (%v), want %q", code, err, c.want)
			}
			repaired := head
			if c.want == "note" {
				extra := note.SignatureLine(c.stranger, make([]byte, 68)) + "\n"
				if head != base+extra {
					t.Fatal("only the extra stranger line may differ")
				}
				repaired = base + note.SignatureLine("stranger", make([]byte, 68)) + "\n"
			} else {
				if !strings.Contains(err.Error(), "timestamp is above") {
					t.Fatalf("the bound must refuse before the cast or Ed25519: %v", err)
				}
				body, sigs, err := note.Split(head)
				if err != nil {
					t.Fatal(err)
				}
				_, originals, err := note.Split(base)
				if err != nil {
					t.Fatal(err)
				}
				different := 0
				for i, sig := range sigs {
					original := originals[i]
					if string(sig.Sig) == string(original.Sig) {
						continue
					}
					different++
					if sig.Name != "norn-witness/pi" || sig.Name != original.Name || string(sig.KeyID) != string(original.KeyID) || binary.BigEndian.Uint64(sig.Sig[:8]) != 1<<63 {
						t.Fatal("only pi's timestamped signature may differ")
					}
					sum := sha256.Sum256([]byte("norn/testvector/v1\nwitness-pi"))
					seed := ed25519.NewKeyFromSeed(sum[:])
					message := []byte("cosignature/v1\ntime 9223372036854775808\n" + body)
					if !ed25519.Verify(seed.Public().(ed25519.PublicKey), message, sig.Sig[8:]) {
						t.Fatal("pi must genuinely sign the unsigned timestamp")
					}
					badLine := note.SignatureLine(sig.Name, append(append([]byte(nil), sig.KeyID...), sig.Sig...))
					goodLine := note.SignatureLine(original.Name, append(append([]byte(nil), original.KeyID...), original.Sig...))
					repaired = strings.Replace(head, badLine, goodLine, 1)
				}
				if different != 1 || repaired != base {
					t.Fatal("the sole witness fault was not repaired")
				}
			}
			runFourteenAnswer(t, servedWith(t, honest, repaired), anchor, "accept")
		})
	}
	t.Run("The well formed non ASCII stranger stays accepted", func(t *testing.T) {
		head := readFile(t, filepath.Join(vectorRoot(), "served-stranger-name", "checkpoint"))
		runFourteenAnswer(t, servedWith(t, honest, head), anchor, "accept")
	})
}
