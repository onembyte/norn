package specdoc

import (
	"strings"
	"testing"
)

// D-076 resolves the three readings recorded by the second cold build.
// Keep the deciding sentences where a reader learns each rule.
func TestD076SettlesProofOrderLineFramingAndDecimalBounds(t *testing.T) {
	doc := load(t)
	for _, tc := range []struct{ section, want, stale string }{
		{"11.1", "4. **version 2 only:** check `split` is not above `size`", "4. conclude a fork **only if"},
		{"11.1", "every proof a file carries is checked before the file is read as a fork (D-076, `fork/bad-consistent-and-bad-split`)", "or a split proof is carried where none is required (step 5) |"},
		{"11.1", "5. conclude a fork **only if `held_root` differs from `conflicting`'s root**", "5. **version 2 only:**"},
		{"9.1", "A missing final line feed is an error whatever the last line holds (`policies/bad-final-comment-no-lf`, D-076)", "| line endings | Every directive line, including the final line, ends in ASCII line feed. A missing final line feed is an error |"},
		{"6", "at most 2⁶³−1 — §4.0's bound on every integer, and one bound for every decimal line a note carries (D-076)", ""},
		{"7", "at most 2⁶³−1 — §4.0's bound on every integer, one bound for every decimal line a note carries (D-076)", ""},
		{"7", "| `deadline` | the unsigned timestamp is invalid, not canonical decimal, or above 2⁶³−1 (D-076) |", "| `deadline` | the unsigned timestamp is invalid or not canonical decimal |"},
		{"10.1", "a size that is not canonical decimal or is above 2⁶³−1 (§6),", ""},
	} {
		t.Run(tc.section+"/"+tc.want, func(t *testing.T) {
			section, ok := doc.Section(tc.section)
			if !ok {
				t.Fatalf("§%s is missing", tc.section)
			}
			body := strings.Join(strings.Fields(section.Body), " ")
			if !strings.Contains(body, strings.Join(strings.Fields(tc.want), " ")) {
				t.Errorf("§%s lacks D-076 passage %q", tc.section, tc.want)
			}
			if tc.stale != "" && strings.Contains(body, tc.stale) {
				t.Errorf("§%s retains replaced passage %q", tc.section, tc.stale)
			}
		})
	}
}
