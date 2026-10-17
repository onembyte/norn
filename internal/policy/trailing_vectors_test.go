package policy

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
)

// D-080 (1), row 6.5l-xv-i (lane BW). Blanks after a policy line's last field
// are not part of it and add no field (§9.1): `policies/trailing-space` and
// `trailing-tab` are the shipped policy with two spaces, or one tab, after
// every line, and each must parse to exactly the fields the policy without
// them does.
func TestTrailingBlanksLeaveEveryPolicyFieldUnchanged(t *testing.T) {
	raw, err := os.ReadFile(vectorRoot() + "/trust.cbor")
	if err != nil {
		t.Fatal(err)
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	base := value.(map[string]any)["policy"].(string)
	want, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(vectorRoot() + "/policies/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name, Says string
			Accept     bool
		}
		Rules map[string]struct{ Section, Says string }
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, suffix string }{{"trailing-space", "  "}, {"trailing-tab", "\t"}} {
		t.Run(c.name, func(t *testing.T) {
			text := policyText(t, c.name)
			if text != strings.ReplaceAll(base, "\n", c.suffix+"\n") {
				t.Fatal("case differs beyond trailing blanks")
			}
			got, err := Parse(text)
			if err != nil {
				t.Fatalf("Go refused: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("parsed policy differs from the policy without blanks")
			}
			found := false
			for _, row := range doc.Cases {
				if row.Name == c.name {
					found = row.Accept && row.Says != ""
				}
			}
			rule := doc.Rules[c.name]
			if !found || rule.Section != "9.1" || rule.Says != "| trailing whitespace | spaces and tabs after the last field are not part of it and add no field (D-080) |" {
				t.Fatal("case or rule is missing")
			}
			t.Log("Go: accepted; every parsed field equals the space-free policy")
		})
	}
}
