package forkevidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/evrefusal"
)

// The carried policy alone changes; restoring it must recover the shipped
// sound evidence, so the point check cannot hide another evidence fault.
func TestD079ShippedCarriedPolicyKeysAreCheckedBesideSoundEvidence(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, "fork", name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var manifest struct {
		Cases []struct{ Name string }
		Codes map[string]string
	}
	if err := json.Unmarshal(read("cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	const name = "bad-policy-small-order-key"
	found := false
	for _, c := range manifest.Cases {
		found = found || c.Name == name
	}
	if !found || manifest.Codes[name] != "policy" {
		t.Error("fork/bad-policy-small-order-key must be listed and coded policy")
	}
	anchor := shippedAnchor(t, root)
	sound := read("evidence.cbor")
	ev, err := Parse(sound)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy); err != nil {
		t.Fatal(err)
	}
	policy := ev.Policy
	ev, err = Parse(read(name + ".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
	code, _ := evrefusal.CodeOf(err)
	if code != evrefusal.Policy || err == nil || !strings.Contains(err.Error(), "valid point") {
		t.Fatalf("Go answers %q (%v), SPEC states policy for an invalid carried point", code, err)
	}
	t.Log("fork/" + name + ": policy; fork/evidence.cbor: accept")
	ev.Policy = policy
	repaired, err := ev.Encode()
	if err != nil || !bytes.Equal(repaired, sound) {
		t.Fatalf("restoring the policy must recover evidence.cbor: %v", err)
	}
}
