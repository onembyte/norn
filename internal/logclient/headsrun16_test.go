package logclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

// Each head uses honest tiles. The policy-only key case alone needs replay;
// publishing a policy log line must never publish a verification key.
func TestRunSixteenHeadsHoldThePlainRules(t *testing.T) {
	for _, tc := range []struct{ name, code string }{
		{"stranger-log-id", "accept"}, {"stranger-pi-id", "accept"},
		{"stranger-del", "accept"}, {"stranger-three-bytes", "note"},
		{"policy-log-only", "log-signature"}, {"forged-pi-without-quorum", "cosignature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(vectorRoot(), "heads-run16")
			var manifest struct {
				Trust     string
				ServeOver string `json:"serve_over"`
				Replay    []string
				Cases     []struct{ Name, File, Reader string }
				Codes     map[string]string
				Rules     map[string]struct{ Section, Says string }
			}
			if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &manifest); err != nil {
				t.Fatal(err)
			}
			if len(manifest.Cases) != 6 || len(manifest.Codes) != 6 || len(manifest.Rules) != 6 || manifest.Trust != "trust.cbor" || manifest.ServeOver != "served" {
				t.Fatal("manifest must carry all six heads, their rules, trust and honest tiles")
			}
			var file, reader string
			for _, c := range manifest.Cases {
				if c.Name == tc.name {
					if file != "" {
						t.Fatal("duplicate case")
					}
					file, reader = c.File, c.Reader
				}
			}
			if file == "" || manifest.Codes[tc.name] != tc.code || manifest.Rules[tc.name].Says == "" {
				t.Fatal("manifest must state this case's fixed answer and rule")
			}
			raw := []byte(readFile(t, filepath.Join(dir, manifest.Trust)))
			if !bytes.Equal(raw, []byte(readFile(t, filepath.Join(vectorRoot(), "trust.cbor")))) {
				t.Fatal("trust must equal fixture trust")
			}
			doc, err := trust.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := doc.Validate(); err != nil {
				t.Fatal(err)
			}
			anchor := Anchor{Anchor: replay.FromTrust(doc), Origin: doc.Origin, LogKeys: []string{doc.LogKey}, Policy: doc.Policy}
			honestDir := filepath.Join(vectorRoot(), manifest.ServeOver)
			honest := readFile(t, filepath.Join(honestDir, "checkpoint"))
			head := readFile(t, filepath.Join(dir, file))
			body, originals, err := note.Split(honest)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "policy-log-only" {
				if reader != "informed" || len(manifest.Replay) != 2 {
					t.Fatal("policy-only key needs exactly the stated history")
				}
				entries := make([][]byte, 2)
				for i, file := range manifest.Replay {
					entries[i] = []byte(readFile(t, filepath.Join(dir, file)))
				}
				if !bytes.Equal(entries[0], []byte(readFile(t, filepath.Join(vectorRoot(), "log", "0-genesis.cbor")))) {
					t.Fatal("history must begin with fixture genesis")
				}
				env, err := entry.Decode(entries[1])
				if err != nil || env.T != "policy" || env.Prev == nil || *env.Prev != 0 {
					t.Fatalf("policy needs prev 0: %v", err)
				}
				for _, sig := range env.Sigs {
					if sig.Role != "root" {
						t.Fatal("policy must be root-signed")
					}
				}
				st := replay.Replay(anchor.Anchor, entries)
				if st.Size != 2 || len(st.Rejected) != 0 {
					t.Fatalf("history must apply: %+v", st.Rejected)
				}
				anchor.Policy = PolicyFrom(st)
				anchor.LogKeys = append(anchor.LogKeys, KeysFrom(doc.Origin, st)...)
				if len(anchor.LogKeys) != 1 {
					t.Fatal("policy must publish no log_key")
				}
				text, lines, err := note.Split(head)
				if err != nil || text != body || len(lines) != 1 {
					t.Fatalf("only the untrusted log line may sign the honest body: %v", err)
				}
				var policyKey string
				for _, line := range strings.Split(anchor.Policy, "\n") {
					if strings.HasPrefix(line, "log ") {
						policyKey = strings.Fields(line)[1]
					}
				}
				if policyKey == doc.LogKey || policyKey == "" {
					t.Fatal("policy must name another key")
				}
				if _, err := note.Verify(head, []string{policyKey}); err != nil {
					t.Fatal("head must verify under the policy-only key", err)
				}
				runFourteenAnswer(t, servedWith(t, honestDir, head), anchor, tc.code)
				runFourteenAnswer(t, servedWith(t, honestDir, honest), anchor, "accept")
				return
			}
			if reader != "fresh" {
				t.Fatal("this case needs only the trust file")
			}
			if tc.name == "forged-pi-without-quorum" {
				text, lines, err := note.Split(head)
				if err != nil || text != body || len(lines) != 2 {
					t.Fatalf("only the log and one forged pi line must remain: %v", err)
				}
				// Repairing pi alone still leaves one witness, below the 2-of-3 quorum.
				repaired := head
				for _, s := range originals {
					if s.Name == "norn-witness/pi" {
						for _, bad := range lines {
							if bad.Name == s.Name {
								if !bytes.Equal(s.KeyID, bad.KeyID) || len(s.Sig) != len(bad.Sig) {
									t.Fatal("pi's name, id and length must stay intact")
								}
								differences := 0
								for i, b := range bad.Sig {
									if b != s.Sig[i] {
										differences++
										if i < 8 || b != s.Sig[i]^1 {
											t.Fatal("only a signature byte may change")
										}
									}
								}
								if differences != 1 {
									t.Fatal("exactly one pi byte must change")
								}
								repaired = strings.Replace(repaired, note.SignatureLine(bad.Name, append(append([]byte(nil), bad.KeyID...), bad.Sig...)), note.SignatureLine(s.Name, append(append([]byte(nil), s.KeyID...), s.Sig...)), 1)
							}
						}
					}
				}
				runFourteenAnswer(t, servedWith(t, honestDir, head), anchor, tc.code)
				runFourteenAnswer(t, servedWith(t, honestDir, repaired), anchor, "quorum")
				runFourteenAnswer(t, servedWith(t, honestDir, honest), anchor, "accept")
				return
			}
			extra := strings.TrimPrefix(head, honest)
			if extra == head || strings.Count(extra, "\n") != 1 {
				t.Fatal("exactly one stranger line must be appended")
			}
			name, payload, ok := strings.Cut(strings.TrimPrefix(strings.TrimSuffix(extra, "\n"), note.SigPrefix), " ")
			data, err := base64.StdEncoding.Strict().DecodeString(payload)
			if !ok || err != nil {
				t.Fatal("stranger must carry canonical base64")
			}
			switch tc.name {
			case "stranger-three-bytes":
				if len(data) != 3 {
					t.Fatal("payload must decode to three bytes")
				}
			case "stranger-del":
				if !strings.Contains(name, "\x7f") {
					t.Fatal("stranger name must contain DEL")
				}
			default:
				key := originals[0]
				if tc.name == "stranger-pi-id" {
					key = originals[1]
				}
				if name == key.Name || len(data) != 4 || !bytes.Equal(data, key.KeyID) {
					t.Fatal("stranger must borrow exactly the key id under another name")
				}
			}
			runFourteenAnswer(t, servedWith(t, honestDir, head), anchor, tc.code)
			runFourteenAnswer(t, servedWith(t, honestDir, honest), anchor, "accept")
		})
	}
}

func TestATamperedLevelOneTileIsTilesAndItsHonestTwinAccepts(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "served-large-bad")
	var m struct {
		ServeOver string `json:"serve_over"`
		Cases     []servedNegative
		Codes     map[string]string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &m); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range m.Cases {
		if c.Name != "level-one-byte-changed" {
			continue
		}
		found = true
		if m.ServeOver != "served-large" || c.Path != "tile/1/000.p/1" || m.Codes[c.Name] != "tiles" {
			t.Fatal("manifest must name the level-1 tile and tiles code")
		}
		honest := filepath.Join(vectorRoot(), m.ServeOver)
		good := readFile(t, filepath.Join(honest, c.Path))
		bad := readFile(t, filepath.Join(dir, c.File))
		if len(good) != 32 || len(bad) != len(good) {
			t.Fatal("only one byte in a width-1 tile may differ")
		}
		differences := 0
		for i := range good {
			if good[i] != bad[i] {
				differences++
				if good[i]^1 != bad[i] {
					t.Fatal("one bit must change")
				}
			}
		}
		if differences != 1 {
			t.Fatal("exactly one byte must change")
		}
		copy := servedWith(t, honest, readFile(t, filepath.Join(honest, "checkpoint")))
		write(t, filepath.Join(copy, c.Path), bad)
		runFourteenAnswer(t, copy, shippedLogAnchor(t), "tiles")
		write(t, filepath.Join(copy, c.Path), good)
		runFourteenAnswer(t, copy, shippedLogAnchor(t), "accept")
	}
	if !found {
		t.Fatal("missing served-large-bad/level-one-byte-changed")
	}
}
