package trust

import (
	"strings"
	"testing"
)

// D-078 (2): a trust file's witness names follow §9.1's name grammar, because
// its policy must name exactly those witnesses and a policy name does. `pi`
// renamed `zürich` in both halves is invalid; renamed `zurich` it is valid.
func TestATrustFileWitnessNameFollowsThePolicyNameGrammar(t *testing.T) {
	for name, valid := range map[string]bool{"zurich": true, "zürich": false} {
		doc := *loadGood(t)
		doc.Witnesses = append([]Witness(nil), doc.Witnesses...)
		for i := range doc.Witnesses {
			if doc.Witnesses[i].Name == "pi" {
				doc.Witnesses[i].Name = name
			}
		}
		doc.Policy = strings.NewReplacer("witness pi ", "witness "+name+" ", " pi ", " "+name+" ").Replace(doc.Policy)
		if !strings.Contains(doc.Policy, "witness "+name+" ") {
			t.Fatal("the fixture trust no longer names pi")
		}
		if err := doc.Validate(); (err == nil) != valid {
			t.Errorf("a trust file whose witness is named %q: valid = %v, want %v (%v)", name, err == nil, valid, err)
		}
	}
}
