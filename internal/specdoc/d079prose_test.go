package specdoc

import (
	"strings"
	"testing"
)

// D-079 (1) and (2), row 6.5l-xiv-f. The policy fork evidence carries parses
// the way every policy does, point check included; a bundle's `device`
// follows §2's grammar, and an entry whose request does not decode names no
// device. Each rule is stated where a reader looks for it: the admission
// list in §3.1, the format rows in §8.1 and §11.1, the closed codes in §10.1
// and §11.1. Keep each sentence; refuse the old words.
func TestRunSixteensAcceptanceDecisionIsStated(t *testing.T) {
	doc := load(t)
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for _, c := range []struct{ name, section, want, stale string }{
		{"the carried policy parses like every policy", "3.1",
			"The policy that fork evidence carries (§11.1) is parsed the same way, though its keys enter no state",
			""},
		{"the carried policy's keys are valid points", "11.1",
			"every verifier key it carries a valid point (§3.1), else the file is `policy`",
			"It MUST parse as `c2sp.org/tlog-policy` — a closed schema"},
		{"the policy code names the point check", "11.1",
			"or carries a verifier key that is not a valid point (§3.1)",
			""},
		{"device follows the grammar", "8.1",
			"in §2's grammar, as §16.1 requires of a request; a label outside it is `bundle`",
			""},
		{"an undecodable request names no device", "8.1",
			"an entry whose request does not decode, or whose body names no `device_id`, names no device, and a bundle around it is `binding` whatever its label says",
			""},
		{"the bundle code names the grammar", "10.1",
			"or a `device` outside §2's grammar",
			""},
		{"the binding code names an entry that names none", "10.1",
			"or names none — an `enroll` whose request does not decode",
			""},
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
