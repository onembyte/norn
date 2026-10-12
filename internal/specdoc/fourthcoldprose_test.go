package specdoc

import (
	"strings"
	"testing"
)

// The fourth cold build read two sentences against the text around them (row
// 6.5l-xii-g). §10.1 still said the outline fetched the entries after its fork
// block, which 6.5l-xii-e-b had changed; and §5.3 closed by calling `quorum
// none` a policy "satisfied at no instant", seven lines after a bullet that
// rejects exactly that reason. Keep the corrections and refuse the old words.
func TestTheFourthColdBuildsProseFindingsAreFixed(t *testing.T) {
	doc := load(t)
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for _, c := range []struct {
		name, section, want, stale string
	}{
		{"head before fork", "10.1",
			"Step 9 rules that out first, which is why §10's outline fetches, frames and hashes the entries before its fork block.",
			"The pseudocode above lists fetching the entries after the fork block for readability"},
		{"no clock", "5.3",
			"When no instant satisfies a policy that requires witnesses, or the policy is `quorum none` and requires nobody (the bullet above), there is **no clock**",
			"When the policy is satisfied at no instant"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, ok := doc.Section(c.section)
			if !ok {
				t.Fatalf("§%s is missing", c.section)
			}
			body := norm(s.Body)
			if !strings.Contains(body, norm(c.want)) {
				t.Errorf("§%s is missing the corrected sentence %q", c.section, c.want)
			}
			if strings.Contains(body, norm(c.stale)) {
				t.Errorf("§%s still says %q", c.section, c.stale)
			}
		})
	}
}
