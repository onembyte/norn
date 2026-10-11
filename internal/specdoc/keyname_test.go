package specdoc

import (
	"strings"
	"testing"
)

// D-074 (f). §7 wrote the key id as "8 hex digits" with no case, and §9.1
// forbade "a Unicode space" in a key name without saying which characters
// those are -- the two implementations read that differently and disagreed on
// U+001C to U+001F. These are the sentences that settle both, and the old
// wording must be gone.
func TestKeyNamesAreASCIIByGrammarAndIDsAreLowercase(t *testing.T) {
	doc := load(t)
	for _, c := range []struct {
		section string
		says    []string
		never   []string
	}{
		{"7", []string{
			"`<name>+<key_id as 8 lowercase hex digits>+<base64(alg ‖ pk)>`",
			"one or more ASCII bytes from `0x21` to `0x7E`, `+` excluded",
		}, []string{"<key_id as 8 hex digits>"}},
		{"9.1", []string{
			"Key names follow §7's ASCII grammar",
		}, []string{"nor a Unicode space"}},
	} {
		section, ok := doc.Section(c.section)
		if !ok {
			t.Fatalf("§%s is missing", c.section)
		}
		body := strings.Join(strings.Fields(section.Body), " ")
		for _, phrase := range c.says {
			if !strings.Contains(body, phrase) {
				t.Errorf("§%s does not state D-074 (f): missing %q", c.section, phrase)
			}
		}
		for _, phrase := range c.never {
			if strings.Contains(body, phrase) {
				t.Errorf("§%s still says %q, which D-074 (f) replaced", c.section, phrase)
			}
		}
	}
}
