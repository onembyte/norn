package specdoc

import (
	"strings"
	"testing"
)

// Cold gate run 15's prose findings (row 6.5l-xiii-b). M2: §9.1 said a policy
// says whether a witness "counts", and §10.1 step 6 checks every listed
// witness's line; a reader taking "counts" for "is checked" accepts a head with
// a bad line from a witness the quorum does not need. L1: the separator is the
// first blank line here and the last in golang.org/x/mod/sumdb/note (v0.41.0,
// bytes.LastIndex), and the two refuse a blank line between signature lines
// with different codes, which §7 and §12.1 denied. L3: a bundle proves an entry
// is in the log, not that replay accepted it. L4: an empty label value is
// accepted by both implementations and was nowhere stated. L5: the first-space
// argument predates D-077's name rule. Keep each correction; refuse the old
// words.
func TestRunFifteensProseFindingsAreFixed(t *testing.T) {
	doc := load(t)
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for _, c := range []struct {
		name, section, want, stale string
	}{
		{"M2 counting is not checking", "9.1",
			"Counting is not checking: a cosignature line whose name **and** key id match a witness the policy lists must verify whether or not its quorum reaches that witness (§10.1 step 6)",
			""},
		{"L1 the library ends the text at the last blank line", "7",
			"They differ in one place, where the text ends: that library ends it at the *last* blank line, this document at the first",
			"there is no second one to choose between"},
		{"L1 the two readings differ by code", "7",
			"here it carries an empty signature line and is `note`; there the lines before it join the text, no trusted line verifies, and it is `log-signature`",
			"the two readings are told apart by no Norn artifact"},
		{"L1 §12.1 no longer says either way covers it", "12.1",
			"A blank line placed **between two signature lines** is another matter: the readings refuse it with different codes, `note` and `log-signature` (§7)",
			"Separating them needs a note whose text is valid with a blank line in it, which this protocol has none of."},
		{"L3 inclusion, not acceptance", "8.1",
			"It does **not** prove that replay accepted that entry",
			"It proves that this device was enrolled"},
		{"L4 the empty label value", "4.0",
			"values ≤ 256 bytes, the empty value included",
			""},
		{"L5 the first space", "7",
			"A reader that split at the *last* space would refuse the same lines, as `note`",
			"which §10 ignores rather than refuses"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, ok := doc.Section(c.section)
			if !ok {
				t.Fatalf("§%s is missing", c.section)
			}
			body := norm(s.Body)
			if !strings.Contains(body, norm(c.want)) {
				t.Errorf("§%s is missing %q", c.section, c.want)
			}
			if c.stale != "" && strings.Contains(body, norm(c.stale)) {
				t.Errorf("§%s still says %q", c.section, c.stale)
			}
		})
	}
}
