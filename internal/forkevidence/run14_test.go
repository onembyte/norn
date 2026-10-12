package forkevidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
)

func checkRunFourteenEvidence(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	anchor := shippedAnchor(t, root)
	var manifest struct{ Codes map[string]string }
	if err := json.Unmarshal(read(t, "fork/cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, code string }{{"bad-policy-unparseable-and-unknown-key", "schema"}, {"bad-unverifiable-conflicting-and-size-mismatch", "conflicting"}, {"bad-size-zero-empty-held", "proof"}} {
		t.Run(c.name, func(t *testing.T) {
			if manifest.Codes[c.name] != c.code {
				t.Errorf("case code %q, want %q", manifest.Codes[c.name], c.code)
			}
			raw := read(t, "fork/"+c.name+".cbor")
			value, err := cbor.DecodeWithin(raw, MaxEvidenceBytes)
			if err != nil {
				t.Fatal(err)
			}
			m := value.(map[string]any)
			check := func(want evrefusal.Code) {
				t.Helper()
				raw, err := cbor.Encode(m)
				if err != nil {
					t.Fatal(err)
				}
				ev, err := Parse(raw)
				if err == nil {
					_, err = Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
				}
				got, _ := evrefusal.CodeOf(err)
				if got != want || (want == "" && err != nil) {
					t.Fatalf("Go answers %q (%v), SPEC states %q", got, err, want)
				}
			}
			check(evrefusal.Code(c.code))
			switch c.code {
			case "schema":
				bad := m["policy"]
				delete(m, "surprise")
				check(evrefusal.Policy)
				m["surprise"] = "an unpermitted evidence key"
				m["policy"] = anchor.Policy
				check(evrefusal.Schema)
				delete(m, "surprise")
				check("")
				m["policy"] = bad
			case "conflicting":
				body, _, err := note.Split(m["conflicting"].(string))
				if err != nil {
					t.Fatal(err)
				}
				cp, err := tlog.ParseCheckpoint(body)
				if err != nil {
					t.Fatal(err)
				}
				if cp.Size == int64(m["size"].(uint64)) {
					t.Fatal("the size fault is absent")
				}
				m["conflicting"] = runFourteenEvidenceSign(t, cp, false)
				check(evrefusal.Size)
				cp.Size = int64(m["size"].(uint64))
				m["conflicting"] = runFourteenEvidenceSign(t, cp, true)
				check(evrefusal.Conflicting)
				m["conflicting"] = runFourteenEvidenceSign(t, cp, false)
				check("")
			case "proof":
				held, err := tlog.Verify(m["held"].(string), []string{anchor.LogKey})
				if err != nil {
					t.Fatal(err)
				}
				conflicting, err := tlog.Verify(m["conflicting"].(string), []string{anchor.LogKey})
				if err != nil {
					t.Fatal(err)
				}
				if held.Size != 0 || conflicting.Size != 0 || held.Root == conflicting.Root || m["size"] != uint64(0) {
					t.Fatal("size-0 rule must stand alone between differing signed roots")
				}
				if string(m["held_root"].([]byte)) != string(held.Root[:]) || len(m["proof"].([]any)) != 0 {
					t.Fatal("held binding and empty proof must be sound")
				}
				// Both heads must retain real cosignatures, not only log signatures.
				for _, field := range []string{"held", "conflicting"} {
					_, sigs, err := note.Split(m[field].(string))
					if err != nil || len(sigs) != 4 {
						t.Fatalf("cosigned zero head: %v", err)
					}
				}
				// Move the same authenticated disagreement to size 1. The
				// held binding and empty proof stay intact, and it proves a
				// fork once the explicit size-0 prohibition no longer applies.
				held.Size, conflicting.Size = 1, 1
				m["size"] = uint64(1)
				m["held"] = runFourteenEvidenceSign(t, held, false)
				m["conflicting"] = runFourteenEvidenceSign(t, conflicting, false)
				check("")
			}
		})
	}
}

// Signatures are rebuilt after a size repair so all unaffected checks remain
// valid. Forging changes one signature byte and preserves its matched key id.
func runFourteenEvidenceSign(t *testing.T, cp tlog.Checkpoint, forge bool) string {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/testvector/v1\nlogkey"))
	head, err := cp.Sign(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	if forge {
		text, block, _ := strings.Cut(head, "\n\n")
		name, blob, _ := strings.Cut(strings.TrimPrefix(strings.TrimSuffix(block, "\n"), note.SigPrefix), " ")
		payload, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			t.Fatal(err)
		}
		payload[len(payload)-1] ^= 1
		head = text + "\n\n" + note.SignatureLine(name, payload) + "\n"
	}
	for i, witness := range []string{"pi", "vps", "friend"} {
		seed := sha256.Sum256([]byte("norn/testvector/v1\nwitness-" + witness))
		line, err := cosign.Sign(cp.Marshal(), "norn-witness/"+witness, ed25519.NewKeyFromSeed(seed[:]), time.Unix(1_760_003_600+int64(i*7), 0))
		if err != nil {
			t.Fatal(err)
		}
		head += line + "\n"
	}
	return head
}
