package specdoc

import (
	"strings"
	"testing"
)

// D-078 (3), cold gate run 15's M3: nothing said what a `log_key` re-publishing
// an active log key does. Keep the rule in §5.1's row and §5.2's code, and keep
// §4.4 from telling the withheld-key story as if only `prev` stopped it.
func TestD078ALogKeyOfAnActiveKeyIsDupKey(t *testing.T) {
	doc := load(t)
	for _, tc := range []struct{ section, want, stale string }{
		{"5.1", "`pk` is not an active log key — `anchor.log_key` or any `pk` in `log_keys` — compared as public-key bytes (`dup-key`, D-078)", ""},
		{"5.2", "a `log_key` whose `pk` an active witness holds or that is already an active log key (§9.1's invariant, D-077 (6), D-078)",
			"a `log_key` whose `pk` an active witness holds (§9.1's invariant, D-077 (6))"},
		{"4.4", "a `log_key` entry reinstates a superseded log key, which since D-078 is `dup-key` as well",
			"a `log_key` entry reinstates a superseded log key;"},
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
