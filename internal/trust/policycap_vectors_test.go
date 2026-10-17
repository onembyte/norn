package trust

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
)

// D-080 (4), row 6.5l-xv-i (lane BW). §4.0's 4096-byte cap is on an entry's
// `text`; a trust file's policy is bounded only by MAX_TRUST_BYTES (§9.1).
// `trust-good/policy-over-4096` is `trust.cbor` with one comment line making
// its policy 4097 bytes, and it is valid.
func TestATrustPolicyAboveTheEntryTextCapIsValid(t *testing.T) {
	const name = "policy-over-4096"
	raw, err := os.ReadFile(vectorRoot() + "/trust-good/" + name + ".cbor")
	if err != nil {
		t.Fatal(err)
	}
	rawSize := len(raw)
	if len(raw) >= MaxTrustBytes {
		t.Fatal("trust file must be below MAX_TRUST_BYTES")
	}
	doc, err := Parse(raw)
	if err == nil {
		err = doc.Validate()
	}
	if err != nil {
		t.Fatalf("Go refused: %v", err)
	}
	if len(doc.Policy) != 4097 {
		t.Fatalf("policy has %d bytes, want 4097", len(doc.Policy))
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	honestRaw, err := os.ReadFile(vectorRoot() + "/trust.cbor")
	if err != nil {
		t.Fatal(err)
	}
	honest, err := cbor.Decode(honestRaw)
	if err != nil {
		t.Fatal(err)
	}
	base := honest.(map[string]any)["policy"].(string)
	padding := strings.TrimPrefix(doc.Policy, base)
	if padding == doc.Policy || !strings.HasPrefix(padding, "#") || strings.Count(padding, "\n") != 1 || !strings.HasSuffix(padding, "\n") {
		t.Fatal("only one comment line may extend the policy")
	}
	value.(map[string]any)["policy"] = base
	if !reflect.DeepEqual(value, honest) {
		t.Fatal("trust file differs beyond policy text")
	}
	raw, err = os.ReadFile(vectorRoot() + "/trust-good/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Cases []string
		Says  map[string]string
		Rules map[string]struct{ Section, Says string }
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range metadata.Cases {
		found = found || item == name
	}
	rule := metadata.Rules[name]
	if !found || !strings.Contains(metadata.Says[name], "comment") || rule.Section != "9.1" || rule.Says != "Its length is bounded only by `MAX_TRUST_BYTES`" {
		t.Fatal("case or rule is missing")
	}
	t.Logf("Go: valid; policy %d bytes, trust file %d bytes", len(doc.Policy), rawSize)
}
