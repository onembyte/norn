package logclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

// These readers have the same replayed state and different acceptance
// histories. Friend is a stranger only to the reader holding no head.
func TestAHeldHeadChecksLinesUnderItsAcceptancePolicy(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "held-policy")
	var meta struct {
		Trust, Initial, Copy string
		Replay               []string
		Readers              map[string]map[string]string
		Cases                []struct{ Name, Reader, File, Says string }
		Codes                map[string]string
		Retains              map[string]string
		Rules                map[string]struct{ Section, Says string }
	}
	raw, e := os.ReadFile(filepath.Join(dir, "cases.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(raw, &meta); e != nil {
		t.Fatal(e)
	}
	if meta.Trust != "../dropped-witness/trust.cbor" || meta.Initial != "log" || meta.Copy != "copy.checkpoint" || !reflect.DeepEqual(meta.Replay, []string{"../dropped-witness/00-genesis.cbor", "../dropped-witness/01-policy-drops-friend.cbor"}) || len(meta.Cases) != 2 {
		t.Fatal("held-policy reader inputs changed")
	}
	if !reflect.DeepEqual(meta.Readers, map[string]map[string]string{
		"held":     {"accept": "log", "replay": "accepted entries", "held_checkpoint": "log/checkpoint", "acceptance_policy": "trust.policy"},
		"replayed": {"replay": "replay", "held_checkpoint": "none", "policy": "replayed"},
	}) || !reflect.DeepEqual(meta.Retains, map[string]string{"checkpoint": "log/checkpoint", "policy": "trust.policy", "quorum_time": "initial acceptance"}) {
		t.Fatal("readers must state acceptance history and retained evidence")
	}
	raw, e = os.ReadFile(filepath.Join(dir, meta.Trust))
	if e != nil {
		t.Fatal(e)
	}
	doc, e := trust.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	fresh := Anchor{Anchor: replay.FromTrust(doc), Origin: doc.Origin, LogKeys: []string{doc.LogKey}, Policy: doc.Policy}
	initial := filepath.Join(dir, meta.Initial)
	held, e := Verify(Dir(initial), fresh)
	if e != nil {
		t.Fatal(e)
	}
	var entries [][]byte
	for _, path := range meta.Replay {
		b, e := os.ReadFile(filepath.Join(dir, path))
		if e != nil {
			t.Fatal(e)
		}
		entries = append(entries, b)
	}
	state := replay.Replay(fresh.Anchor, entries)
	if len(state.Rejected) != 0 || !reflect.DeepEqual(held.Served, entries) || !reflect.DeepEqual(held.State, state) || held.Checkpoint.Size != 2 || len(held.Cosignatures) != 3 {
		t.Fatal("initial log must accept and replay exactly the two policy entries")
	}
	current := PolicyFrom(state)
	if held.AcceptancePolicy != doc.Policy || !strings.Contains(doc.Policy, "witness friend ") || strings.Contains(current, "witness friend ") || current == doc.Policy {
		t.Fatal("only accepting policy must list friend")
	}
	honest := readFile(t, filepath.Join(initial, "checkpoint"))
	forged := readFile(t, filepath.Join(dir, meta.Copy))
	if forged != forgeWitnessLine(t, honest, "friend") {
		t.Fatal("copy must flip only friend's existing signature's last byte")
	}
	before := *held
	before.Cosignatures = append([]cosign.Cosignature(nil), held.Cosignatures...)
	if held.QuorumTime == nil {
		t.Fatal("the initial quorum must supply T")
	}
	at := *held.QuorumTime
	before.QuorumTime = &at
	seen := map[string]bool{}
	for _, c := range meta.Cases {
		if seen[c.Name] || c.File != meta.Copy || c.Says == "" {
			t.Fatal("case missing, duplicated or not the exact copy")
		}
		seen[c.Name] = true
		want := "accept"
		section, phrase := "9.4", "A `policy` entry supersedes `norn.trust.policy` for every checkpoint"
		if c.Reader == "held" {
			want, section, phrase = "cosignature", "5.3", "names a witness that policy lists, by name and key id"
		} else if c.Reader != "replayed" {
			t.Fatal("unknown reader")
		}
		if meta.Codes[c.Name] != want || meta.Rules[c.Name].Section != section || meta.Rules[c.Name].Says != phrase {
			t.Fatal("case code or rule changed")
		}
		for _, incremental := range []bool{false, true} {
			t.Run(c.Name+map[bool]string{false: "/Verify", true: "/VerifyFrom"}[incremental], func(t *testing.T) {
				a := fresh
				a.Policy = current
				var previous *Result
				if c.Reader == "held" {
					a.Stored, a.Held, a.StoredResult = &held.Checkpoint, held.Tree, held
					previous = held
				}
				read := func(head string) (*Result, error) {
					overlay := servedWith(t, initial, head)
					if incremental {
						return VerifyFrom(previous, Dir(overlay), a)
					}
					return Verify(Dir(overlay), a)
				}
				got, e := read(forged)
				code, _ := refusal.CodeOf(e)
				if want == "accept" {
					if e != nil {
						t.Fatal(e)
					}
					if got.AcceptancePolicy != current {
						t.Fatal("unheld reader must accept under replayed policy")
					}
				} else if string(code) != want {
					t.Fatalf("held copy = %q, want cosignature: %v", code, e)
				}
				if held.SignedCheckpoint != before.SignedCheckpoint || held.AcceptancePolicy != before.AcceptancePolicy || !reflect.DeepEqual(held.Cosignatures, before.Cosignatures) || !reflect.DeepEqual(held.QuorumTime, before.QuorumTime) {
					t.Fatal("refusal changed held note, cosignatures, accepting policy or T")
				}
				repaired, e := read(honest)
				if e != nil {
					t.Fatalf("honest copy repair: %v", e)
				}
				if c.Reader == "held" && (repaired.SignedCheckpoint != before.SignedCheckpoint || repaired.AcceptancePolicy != before.AcceptancePolicy || !reflect.DeepEqual(repaired.Cosignatures, before.Cosignatures) || !reflect.DeepEqual(repaired.QuorumTime, before.QuorumTime)) {
					t.Fatal("honest reread changed acceptance")
				}
			})
		}
	}
	if !seen["held-forged-friend"] || !seen["replayed-forged-friend"] {
		t.Fatal("both named readers are required")
	}
}
