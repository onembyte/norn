package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-078 (row 6.5l-xiii-d). Cold gate run 15 showed that recording a refused
// entry's signed content lets a copy with its signatures stripped, appended
// first, cancel the genuine entry: the revoke never applies, every conforming
// reader agrees, and no receipt proves it. The decision keeps every entry's
// bytes and only an accepted entry's content, in sets of their own, and
// settles four smaller acceptance questions. Until the rows that apply it
// land, it lives in four documents that must agree: the decision itself, the
// note under the decision it amends, the plan's list, and the threat model's
// open row.
func TestTheDuplicateRuleDecisionIsRecorded(t *testing.T) {
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(raw)), " ")
	}
	decisions := read("DECISIONS.md")
	if !strings.Contains(decisions, "## D-078") {
		t.Error("DECISIONS.md has no D-078")
	}
	start := strings.Index(decisions, "## D-070")
	end := strings.Index(decisions, "## D-071")
	if start < 0 || end < start {
		t.Fatal("DECISIONS.md has no D-070 to read")
	}
	if !strings.Contains(decisions[start:end], "D-078") {
		t.Error("DECISIONS.md D-070 does not say which part of it D-078 supersedes")
	}
	for _, c := range []struct{ file, want string }{
		{"HARDENING-PLAN.md", "D-078 (taken 2026-10-14"},
		{"THREAT-MODEL.md", "Open until 6.5l-xiii-e lands (D-078"},
	} {
		if !strings.Contains(read(c.file), c.want) {
			t.Errorf("%s does not say %q", c.file, c.want)
		}
	}
}
