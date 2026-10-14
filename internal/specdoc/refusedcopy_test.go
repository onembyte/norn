package specdoc

import (
	"strings"
	"testing"
)

// D-078 (1), cold gate run 15's H1 and H2. Replay keeps every entry's bytes and
// only an applied entry's signed content, in sets that are never compared, so
// a refused copy with its signatures stripped no longer cancels the genuine
// entry after it. Keep the deciding sentences where a reader learns the rule,
// and keep the ones they replace out.
func TestD078ARefusedEntryBurnsOnlyItsBytes(t *testing.T) {
	doc := load(t)
	for _, tc := range []struct{ section, want, stale string }{
		{"4.0", "The byte key of every entry that reaches §5.1 step 1, accepted or not",
			"The de-duplication identity of an entry that does **not** decode"},
		{"4.0", "the content key of an entry that **does** decode, recorded only once replay **applies** it (D-070, D-078)",
			"the de-duplication identity of every entry that **does** decode (D-070)"},
		{"5.1", "Replay keeps two seen sets, and an `entry_hash` and a `content_hash` are never compared with each other",
			"to the seen set, **whether or not it is later rejected** (D-031): the first appearance of a signed content is the only one replay will ever apply"},
		{"5.1", "a **refused** entry burns nothing but its bytes", ""},
		{"5.2", "| `dup-entry` | the entry's `entry_hash` was already seen, or it decodes and its `content_hash` is an applied entry's (§5.1 step 1, D-078) |",
			"| `dup-entry` | the duplicate key — `content_hash` for an entry that decodes, `entry_hash` otherwise (§5.1 step 1) — already seen |"},
		{"4.4", "`dup-entry` (§5.1 step 1) catches only a byte copy or a copy of an applied entry",
			"`dup-entry` (§5.1 step 1) catches only identical bytes"},
	} {
		t.Run(tc.section+"/"+tc.want, func(t *testing.T) {
			section, ok := doc.Section(tc.section)
			if !ok {
				t.Fatalf("§%s is missing", tc.section)
			}
			body := strings.Join(strings.Fields(section.Body), " ")
			if !strings.Contains(body, strings.Join(strings.Fields(tc.want), " ")) {
				t.Errorf("§%s lacks D-078 passage %q", tc.section, tc.want)
			}
			if tc.stale != "" && strings.Contains(body, strings.Join(strings.Fields(tc.stale), " ")) {
				t.Errorf("§%s still says %q", tc.section, tc.stale)
			}
		})
	}
}
