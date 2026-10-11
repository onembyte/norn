package specdoc

import (
	"strings"
	"testing"
)

// D-074 (e) resolves the placement of directives independently of name
// resolution. Both statements belong in the grammar a reader implements.
func TestPolicyLinesMayAppearInAnyOrderButNamesResolveInOrder(t *testing.T) {
	section, ok := load(t).Section("9.1")
	if !ok {
		t.Fatal("§9.1 is missing")
	}
	for _, phrase := range []string{
		"lines may appear in **any order**",
		"nothing defined later changes an earlier line",
	} {
		if !strings.Contains(section.Body, phrase) {
			t.Errorf("§9.1 does not state D-074 (e): missing %q", phrase)
		}
	}
}
