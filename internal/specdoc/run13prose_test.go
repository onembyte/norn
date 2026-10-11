package specdoc

import (
	"strings"
	"testing"
)

// Cold gate run 13's prose findings (D4, D11, D19), the ones no sub-row of
// H5-f took. Each sentence below replaces one the run showed to be wrong or
// missing; the wrong one must be gone.
func TestRunThirteensProseFindingsAreFixed(t *testing.T) {
	doc := load(t)
	for _, c := range []struct {
		section, why string
		says, never  []string
	}{
		{"5.1", "D4: the order is normative, and an unvectored one is untested, not optional",
			[]string{"still normative, merely untested"},
			[]string{"an ordering a second implementation may reverse"}},
		{"9.4", "D11: the name a learned log key signs under",
			[]string{"A learned key is the verifier key `<origin>+<id>+base64(0x01 ‖ pk)`"},
			nil},
		{"12.1", "D19: the coverage rows say what the suite does, in both directions",
			[]string{
				"`state.json` and the `.json` mirrors of entry vectors",
				"`replayed_policy_quorum_time` is computed under a three-of-three policy",
			},
			[]string{"| §14 canonical JSON | every `.json`", "**The median, as distinct from the k-th newest.**"}},
	} {
		section, ok := doc.Section(c.section)
		if !ok {
			t.Fatalf("§%s is missing", c.section)
		}
		body := strings.Join(strings.Fields(section.Body), " ")
		for _, phrase := range c.says {
			if !strings.Contains(body, phrase) {
				t.Errorf("§%s (%s): missing %q", c.section, c.why, phrase)
			}
		}
		for _, phrase := range c.never {
			if strings.Contains(body, phrase) {
				t.Errorf("§%s (%s): still says %q", c.section, c.why, phrase)
			}
		}
	}
}
