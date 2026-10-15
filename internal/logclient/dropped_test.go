package logclient

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

// The same forged line is checked while friend is named and ignored after
// replay drops it. The trust file still lists friend in both cases.
func TestADroppedWitnessIsAStrangerOnlyAfterReplayingThePolicy(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "dropped-witness")
	var manifest struct {
		Trust     string
		ServeOver string `json:"serve_over"`
		Replay    []string
		Cases     []struct{ Name, File, Reader string }
		Codes     map[string]string
	}
	raw := []byte(readFile(t, filepath.Join(dir, "cases.json")))
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Trust != "trust.cbor" || manifest.ServeOver != "served" || len(manifest.Replay) != 2 || len(manifest.Cases) != 2 || len(manifest.Codes) != 2 {
		t.Fatal("manifest must name its trust, tiles, two replay entries and both answers")
	}
	doc, err := trust.Parse([]byte(readFile(t, filepath.Join(dir, manifest.Trust))))
	if err != nil {
		t.Fatal(err)
	}
	fresh := Anchor{Anchor: replay.FromTrust(doc), Origin: doc.Origin, LogKeys: []string{doc.LogKey}, Policy: doc.Policy}
	old, err := policy.Parse(fresh.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Witnesses) != 3 || !reflect.DeepEqual(old.WitnessNames(), []string{"pi", "vps", "friend"}) {
		t.Fatal("trust and its policy must still list all three witnesses")
	}
	entries := make([][]byte, len(manifest.Replay))
	for i, file := range manifest.Replay {
		entries[i] = []byte(readFile(t, filepath.Join(dir, file)))
	}
	if !bytes.Equal(entries[0], []byte(readFile(t, filepath.Join(vectorRoot(), "log", "0-genesis.cbor")))) {
		t.Fatal("replay must start with the fixture genesis")
	}
	env, err := entry.Decode(entries[1])
	if err != nil || env.T != "policy" || env.Prev == nil || *env.Prev != 0 {
		t.Fatalf("second entry must be policy with prev 0: %v", err)
	}
	for _, sig := range env.Sigs {
		if sig.Role != "root" {
			t.Fatal("policy must be root-signed")
		}
	}
	st := replay.Replay(fresh.Anchor, entries)
	if st.Size != 2 || len(st.Rejected) != 0 {
		t.Fatalf("policy replay did not apply: %+v", st.Rejected)
	}
	informed := fresh
	informed.Policy = PolicyFrom(st)
	current, err := policy.Parse(informed.Policy)
	if err != nil || !reflect.DeepEqual(current.WitnessNames(), []string{"pi", "vps"}) || !current.Satisfied([]string{"pi", "vps"}) {
		t.Fatalf("replayed policy must drop friend and accept pi and vps: %v", err)
	}
	forged := readFile(t, filepath.Join(dir, "forged-friend.checkpoint"))
	honest := readFile(t, filepath.Join(vectorRoot(), manifest.ServeOver, "checkpoint"))
	body, lines, err := note.Split(forged)
	if err != nil {
		t.Fatal(err)
	}
	text, originals, err := note.Split(honest)
	if err != nil || body != text || len(lines) != len(originals) {
		t.Fatalf("only friend's signature may differ from the honest head: %v", err)
	}
	different := 0
	for i, line := range lines {
		original := originals[i]
		if line.Name != original.Name || !bytes.Equal(line.KeyID, original.KeyID) || len(line.Sig) != len(original.Sig) {
			t.Fatal("all signature names, key ids and lengths must stay unchanged")
		}
		for j, value := range line.Sig {
			if value != original.Sig[j] {
				different++
				if line.Name != "norn-witness/friend" || j < 8 || value != original.Sig[j]^1 {
					t.Fatal("only one friend signature byte may change")
				}
			}
		}
	}
	if different != 1 {
		t.Fatal("exactly one friend signature byte must change")
	}
	if _, err := cosign.Verify(forged, old.Keys()); err == nil {
		t.Fatal("friend's matching signature must not verify under the trust policy")
	} else if code, _ := refusal.CodeOf(err); code != refusal.Cosignature {
		t.Fatalf("wrong forged-line fault: %v", err)
	}
	sigs, err := cosign.Verify(forged, current.Keys())
	if err != nil || len(sigs) != 2 {
		t.Fatalf("remaining witnesses must both verify: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			want := map[string]string{"friend-after-drop": "accept", "friend-before-replay": "cosignature"}[c.Name]
			if want == "" || seen[c.Name] || manifest.Codes[c.Name] != want || c.File != "forged-friend.checkpoint" {
				t.Fatal("manifest must name each fixed answer once for the same head")
			}
			seen[c.Name] = true
			anchor := fresh
			if c.Reader == "informed" && c.Name == "friend-after-drop" {
				anchor = informed
			} else if c.Reader != "fresh" || c.Name != "friend-before-replay" {
				t.Fatal("case names the wrong reader history")
			}
			runFourteenAnswer(t, servedWith(t, filepath.Join(vectorRoot(), manifest.ServeOver), forged), anchor, want)
		})
	}
}
