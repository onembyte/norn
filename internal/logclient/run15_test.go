package logclient

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

// The empty line is inside the signature block, so removing only that line
// must recover the honest head and its acceptance over the same tiles.
func TestABlankLineBetweenSignatureLinesIsNoteAndItsRemovalAccepts(t *testing.T) {
	const name = "45-blank-line-between-signatures"
	honest := filepath.Join(vectorRoot(), "served")
	base := readFile(t, filepath.Join(honest, "checkpoint"))
	var manifest struct {
		Cases []string
		Codes map[string]string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", "cases.json"))), &manifest); err != nil {
		t.Fatal(err)
	}
	found := false
	for i, c := range manifest.Cases {
		if i > 0 && c <= manifest.Cases[i-1] {
			t.Fatal("cases must remain in number order")
		}
		if c == name {
			found = true
		}
	}
	if !found {
		t.Fatal("missing checkpoints-bad/" + name)
	}
	if manifest.Codes[name] != "note" {
		t.Fatalf("manifest code %q, SPEC states note", manifest.Codes[name])
	}
	head := readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", name+".checkpoint"))
	text, block, ok := strings.Cut(base, "\n\n")
	first, rest, framed := strings.Cut(block, "\n")
	if !ok || !framed || !strings.HasPrefix(first, note.SigPrefix) || !strings.HasPrefix(rest, note.SigPrefix) || head != text+"\n\n"+first+"\n\n"+rest {
		t.Fatal("only one empty line between the first two signature lines may differ")
	}
	runFourteenAnswer(t, servedWith(t, honest, head), shippedLogAnchor(t), "note")
	repaired := text + "\n\n" + strings.Replace(head[len(text)+2:], "\n\n", "\n", 1)
	if repaired != base {
		t.Fatal("removing the empty line must reproduce served/checkpoint exactly")
	}
	runFourteenAnswer(t, servedWith(t, honest, repaired), shippedLogAnchor(t), "accept")
}

// Listing a witness and using it in the quorum are independent. The trust
// remains valid, and every matching line must verify before quorum checking.
func TestAListedWitnessOutsideTheQuorumIsCheckedAndItsRepairAccepts(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "unreached-witness")
	var manifest struct {
		ServeOver string `json:"serve_over"`
		Trust     string
		Cases     []struct{ Name, File string }
		Codes     map[string]string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ServeOver != "served" || manifest.Trust != "trust.cbor" || len(manifest.Cases) != 2 || len(manifest.Codes) != 2 {
		t.Fatal("manifest must name its trust, honest tiles and both cases")
	}
	if manifest.Cases[0].Name != "honest-head" || manifest.Cases[1].Name != "forged-friend" {
		t.Fatal("manifest must list each named case exactly once")
	}
	raw := []byte(readFile(t, filepath.Join(dir, manifest.Trust)))
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("Go refuses this trust (%v), SPEC §9.1 permits it", err)
	}
	original, err := trust.Parse([]byte(readFile(t, filepath.Join(vectorRoot(), "trust.cbor"))))
	if err != nil {
		t.Fatal(err)
	}
	original.Policy = doc.Policy
	encoded, err := original.Encode()
	if err != nil || !bytes.Equal(encoded, raw) {
		t.Fatalf("only the trust policy may differ: %v", err)
	}
	rules, err := policy.Parse(doc.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rules.WitnessNames(), []string{"pi", "vps", "friend"}) || !strings.Contains(doc.Policy, "group home 2 pi vps\nquorum home\n") {
		t.Fatal("policy must list three witnesses and require pi and vps alone, 2 of 2")
	}
	for _, names := range [][]string{{"pi"}, {"vps"}, {"pi", "friend"}, {"vps", "friend"}} {
		if rules.Satisfied(names) {
			t.Fatalf("quorum unexpectedly met by %v", names)
		}
	}
	if !rules.Satisfied([]string{"pi", "vps"}) {
		t.Fatal("pi and vps must satisfy the quorum without friend")
	}
	anchor := Anchor{Anchor: replay.FromTrust(doc), LogKeys: []string{doc.LogKey}, Origin: doc.Origin, Policy: doc.Policy}
	honest := filepath.Join(vectorRoot(), manifest.ServeOver)
	base := readFile(t, filepath.Join(honest, "checkpoint"))
	_, originals, err := note.Split(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			want := map[string]string{"honest-head": "accept", "forged-friend": "cosignature"}[c.Name]
			if want == "" || manifest.Codes[c.Name] != want {
				t.Fatalf("manifest code %q, SPEC states %q", manifest.Codes[c.Name], want)
			}
			head := readFile(t, filepath.Join(dir, c.File))
			runFourteenAnswer(t, servedWith(t, honest, head), anchor, want)
			if want == "accept" {
				if head != base {
					t.Fatal("accepted head must be the honest head byte for byte")
				}
				sigs, err := cosign.Verify(head, rules.Keys())
				if err != nil || len(sigs) != 3 {
					t.Fatalf("all three listed lines must verify: %v", err)
				}
				return
			}
			body, sigs, err := note.Split(head)
			if err != nil || len(sigs) != len(originals) {
				t.Fatalf("forged head must still frame: %v", err)
			}
			baseBody, _, _ := note.Split(base)
			if body != baseBody {
				t.Fatal("signed text may not change")
			}
			different := 0
			repaired := head
			for i, sig := range sigs {
				original := originals[i]
				if sig.Name != original.Name || !bytes.Equal(sig.KeyID, original.KeyID) || len(sig.Sig) != len(original.Sig) {
					t.Fatal("names, key ids and payload lengths must remain unchanged")
				}
				for j, value := range sig.Sig {
					if value != original.Sig[j] {
						different++
						if sig.Name != "norn-witness/friend" || j < 8 || value != original.Sig[j]^1 {
							t.Fatal("only one friend signature byte may change")
						}
					}
				}
				if !bytes.Equal(sig.Sig, original.Sig) {
					badLine := note.SignatureLine(sig.Name, append(append([]byte(nil), sig.KeyID...), sig.Sig...))
					goodLine := note.SignatureLine(original.Name, append(append([]byte(nil), original.KeyID...), original.Sig...))
					repaired = strings.Replace(repaired, badLine, goodLine, 1)
				}
			}
			if different != 1 || repaired != base {
				t.Fatal("restoring friend's sole changed signature byte must reproduce the honest head")
			}
			runFourteenAnswer(t, servedWith(t, honest, repaired), anchor, "accept")
		})
	}
}
