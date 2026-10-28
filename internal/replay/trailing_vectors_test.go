package replay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/policy"
)

// D-080 (1) in replay, row 6.5l-xv-i (lane BW). `log-rules/26` is a `policy`
// signed by the current roots whose every line ends in a space: it applies,
// the state keeps its text verbatim, as it keeps any policy's, and that text
// parses exactly as the policy without the spaces.
func TestARootSignedPolicyWithTrailingSpacesApplies(t *testing.T) {
	const name = "26-policy-trailing-space"
	dir := vectorRoot() + "/log-rules"
	raw, err := os.ReadFile(dir + "/" + name + ".cbor")
	if err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	anchor, inputs, manifest := loadCase(t, dir)
	if len(inputs) != 45 || manifest.Entries[25].Name != "25-enroll-without-expires" || manifest.Entries[26].Name != name || manifest.Entries[26].Reason != "" {
		t.Fatal("case must follow entry 25 and apply")
	}
	before := Replay(anchor, inputs[:26])
	if env.T != "policy" || env.Prev == nil || *env.Prev != before.Versions["policy"] || uint64(len(env.Sigs)) != before.RootThr {
		t.Fatal("policy is not signed at its current version and root threshold")
	}
	for _, sig := range env.Sigs {
		pk, err := hex.DecodeString(before.Roots[sig.Kid])
		if err != nil {
			t.Fatal(err)
		}
		valid, err := entry.Verify(env, sig, pk)
		if err != nil || !valid || sig.Role != "root" {
			t.Fatalf("policy needs valid current root signatures: %v", err)
		}
	}
	text := env.Body["text"].(string)
	if text != strings.ReplaceAll(anchor.Policy, "\n", " \n") {
		t.Fatal("policy differs beyond trailing spaces")
	}
	// Entry 33 supersedes this policy, so its storage and grammar are
	// checked at its own prefix before comparing the complete final state.
	atPolicy := Replay(anchor, inputs[:27])
	if got := lastOutcome(atPolicy, 26); got != "" {
		t.Fatalf("Go = %q, want applied", got)
	}
	if atPolicy.Versions["policy"] != 26 || atPolicy.Policy != text {
		t.Fatal("policy was not stored verbatim at version 26")
	}
	got, err := policy.Parse(atPolicy.Policy)
	if err != nil {
		t.Fatal(err)
	}
	want, err := policy.Parse(anchor.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("stored policy parses differently from space-free text")
	}
	final := Replay(anchor, inputs)
	replacement, err := entry.Decode(inputs[33])
	if err != nil {
		t.Fatal(err)
	}
	if final.Versions["policy"] != 33 || final.Policy != replacement.Body["text"] {
		t.Fatal("replacement policy was not retained through the later params")
	}
	stateJSON, err := final.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(dir + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stateJSON, expected) {
		t.Fatal("Go state differs from reference state.json")
	}
	metadata, err := os.ReadFile(dir + "/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules map[string]struct{ Section, Says string }
	}
	if err := json.Unmarshal(metadata, &doc); err != nil {
		t.Fatal(err)
	}
	rule := doc.Rules[name]
	if rule.Section != "9.1" || rule.Says != "| trailing whitespace | spaces and tabs after the last field are not part of it and add no field (D-080) |" {
		t.Fatal("missing trailing whitespace rule")
	}
	t.Log("Go: applied; state.json matches, parsed policy equals the space-free policy")
}
