package specdoc

import (
	"strings"
	"testing"
)

// D-074 (a). §9.4 lets the roots rotate the log key inside the log, and a node
// verifies checkpoints under every key it has learned that way -- but §7 and
// §8.1 said a receipt and a bundle verify under "the anchored log key", so
// once the overlap passed, no receipt or bundle the log made could be checked
// by anybody, including the node that had replayed the rotation. These are
// the sentences that say otherwise; a reader of SPEC alone must find them.
func TestBundlesAndReceiptsVerifyUnderEveryTrustedLogKey(t *testing.T) {
	doc := load(t)
	for _, c := range []struct {
		section string
		phrases []string
	}{
		{"7", []string{
			"the log keys the verifier trusts for the anchored origin (§9.4: the trust file's, plus every `log_key` of a state it has accepted)",
			"The note MUST verify under a log key the verifier trusts",
			"the signature line's key name and key id select the key",
			"lines naming no trusted key are ignored",
		}},
		{"8", []string{
			"a bundle made after a rotation is checkable by a reader that has replayed the log through the rotation; one holding only `norn.trust` sees `log-signature`",
			"A trust file issued later for the same network names the same initial key (§9.4)",
			"v1 retires no log key, in the log or out of it",
		}},
		{"8.1", []string{
			"under the log keys the verifier trusts (§9.4: the trust file's, plus every `log_key` of a state it has accepted) and the policy of that state",
		}},
	} {
		section, ok := doc.Section(c.section)
		if !ok {
			t.Fatalf("§%s is missing", c.section)
		}
		text := strings.Join(strings.Fields(section.Body), " ")
		for _, phrase := range c.phrases {
			if !strings.Contains(text, phrase) {
				t.Errorf("§%s does not state D-074 (a): missing %q", c.section, phrase)
			}
		}
	}
}
