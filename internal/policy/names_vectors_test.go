package policy

import (
	"strings"
	"testing"
)

// D-078 names are labels, so the grammar applies without changing key names.
func TestShippedPolicyNamesHaveOnlyTheirNamedFault(t *testing.T) {
	for _, c := range []struct {
		name, bad, good string
		accept          bool
	}{
		{"bad-witness-name-not-ascii", "zürich", "zurich", false},
		{"bad-group-name-plus", "a+b", "ab", false},
		{"bad-witness-name-one-past-the-cap", strings.Repeat("a", 65), strings.Repeat("a", 64), false},
		{"witness-name-at-the-cap", strings.Repeat("a", 64), strings.Repeat("a", 64), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := policyText(t, c.name)
			if !strings.Contains(text, c.bad) {
				t.Fatal("named fault missing")
			}
			found := false
			for _, item := range policyCases(t) {
				if item.Name == c.name {
					found = true
					if item.Accept != c.accept {
						t.Fatal("manifest differs from stated answer")
					}
				}
			}
			if !found {
				t.Fatal("case missing from manifest")
			}
			_, err := Parse(text)
			if (err == nil) != c.accept {
				t.Fatalf("Go accept = %v, want %v", err == nil, c.accept)
			}
			if _, err := Parse(strings.ReplaceAll(text, c.bad, c.good)); err != nil {
				t.Fatalf("name repair: %v", err)
			}
		})
	}
}
