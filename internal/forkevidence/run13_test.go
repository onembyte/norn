package forkevidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/tlog"
)

// Cold gate run 13, D14. A suite with only same-size negatives lets a reader
// refuse the simplest equivocation unconditionally. Both heads must verify,
// and the evidence must bind its held root without a consistency proof.
func TestASoundSameSizeForkIsVectored(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var manifest struct {
		Sound []string `json:"sound"`
	}
	if err := json.Unmarshal(read("fork/cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	const name = "evidence-at-same-size"
	if !slices.Contains(manifest.Sound, name) {
		t.Fatalf("fork/cases.json sound lacks %s", name)
	}
	ev, err := Parse(read("fork/" + name + ".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor := shippedAnchor(t, root)
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		t.Fatal(err)
	}
	held, err := verified(ev.Held, anchor.Origin, []string{anchor.LogKey}, rules)
	if err != nil {
		t.Fatal(err)
	}
	conflicting, err := verified(ev.Conflicting, anchor.Origin, []string{anchor.LogKey}, rules)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Held != string(read("served/checkpoint")) || ev.Size != held.Size || ev.Size != conflicting.Size || held.Root == conflicting.Root || !bytes.Equal(ev.HeldRoot, held.Root[:]) || len(ev.Proof) != 0 {
		t.Fatal("not the served head and a different root at the same size with a bound held_root and empty proof")
	}
	for _, signed := range []string{ev.Held, ev.Conflicting} {
		signatures, err := cosign.Verify(signed, rules.Keys())
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, s := range signatures {
			names[s.Name] = true
		}
		if len(names) != 3 {
			t.Fatalf("%d witnesses cosigned, want all three", len(names))
		}
	}
	finding, err := Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
	if err != nil {
		t.Fatalf("same-size fork was refused: %v", err)
	}
	if finding.Size != held.Size || finding.Held != held.Root || finding.Claimed != conflicting.Root {
		t.Fatalf("wrong finding: %+v", finding)
	}
}

// D4 orders the carried policy before the held checkpoint in §11.1's closed
// code table. Repairing only the policy must expose the foreign held head.
func TestTheCarriedPolicyIsCheckedBeforeAForeignHeldHead(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	const name = "bad-policy-unparseable-and-foreign-held"
	raw, err := os.ReadFile(filepath.Join(root, "fork", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Codes map[string]evrefusal.Code `json:"codes"`
	}
	raw, err = os.ReadFile(filepath.Join(root, "fork", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Codes[name] != evrefusal.Policy {
		t.Fatalf("case code is %q, want policy", manifest.Codes[name])
	}
	if _, err := policy.Parse(ev.Policy); err == nil {
		t.Fatal("carried policy parses")
	}
	anchor := shippedAnchor(t, root)
	body, _, err := note.Split(ev.Held)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := tlog.ParseCheckpoint(body)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Origin == anchor.Origin {
		t.Fatal("held head is not foreign")
	}
	served, err := os.ReadFile(filepath.Join(root, "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	held, err := tlog.Verify(string(served), []string{anchor.LogKey})
	if err != nil {
		t.Fatal(err)
	}
	if cp.Size != held.Size || cp.Root != held.Root {
		t.Fatal("foreign held head also changed the tree, adding an unrelated proof fault")
	}
	_, err = Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
	if got, _ := evrefusal.CodeOf(err); got != evrefusal.Policy {
		t.Fatalf("two faults refused as %q, want policy: %v", got, err)
	}
	ev.Policy = anchor.Policy
	_, err = Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
	if got, _ := evrefusal.CodeOf(err); got != evrefusal.Held {
		t.Fatalf("repaired policy refused as %q, want held: %v", got, err)
	}
}
