package specdoc

import (
	"strings"
	"testing"
)

// D-074 (c), as corrected 2026-10-10. The preamble let the reused C2SP
// specifications win every conflict while §10 imposed stricter note rules,
// and §7 made every line's decoded length 68 or 76 -- a stranger's line
// included, whose algorithm §7 itself says a reader cannot know. Read that
// way, one cosignature on a third algorithm made a shared log unreadable to
// every Norn node. These are the sentences that settle it; a reader of SPEC
// alone must find them, and must not find the old rule beside them.
func TestTheSignedNoteProfileIsStatedOnce(t *testing.T) {
	text := specText(t)
	end := strings.Index(text, "\n## 1.")
	if end < 0 {
		t.Fatal("SPEC.md has no §1, so the preamble cannot be bounded")
	}
	preamble := strings.Join(strings.Fields(text[:end]), " ")
	if !strings.Contains(preamble, "§7 and §10 are Norn's profile of `c2sp.org/signed-note`, `tlog-checkpoint` and `tlog-cosignature`, and govern where they are stricter") {
		t.Error("the preamble does not say §7 and §10 govern where they are stricter " +
			"than the signed-note specifications they otherwise defer to")
	}

	doc := load(t)
	for _, c := range []struct {
		section string
		says    []string
		never   []string
	}{
		{"7", []string{
			"canonical padded base64 that decodes to at least the 4-byte `key_id`",
			"A line that matches no trusted key is ignored whatever its length",
			"The signed text and every signature line MUST be valid UTF-8",
			"`checkpoints-bad/20-signature-payload-too-long`) and a 76-byte payload under the log's `0x01` key are both `log-signature` failures",
		}, []string{
			"Any other decoded length is malformed note framing",
			"accepts a decoded payload of **exactly** 68 or 76 bytes",
		}},
		{"10.1", []string{
			"canonical padded base64 of at least a 4-byte key id, text or a line that is not UTF-8",
			"and so does any other length but 68 (`checkpoints-bad/20-signature-payload-too-long`)",
		}, []string{
			"padded base64 of **exactly** 68 or 76 bytes",
		}},
	} {
		section, ok := doc.Section(c.section)
		if !ok {
			t.Fatalf("§%s is missing", c.section)
		}
		body := strings.Join(strings.Fields(section.Body), " ")
		for _, phrase := range c.says {
			if !strings.Contains(body, phrase) {
				t.Errorf("§%s does not state D-074 (c): missing %q", c.section, phrase)
			}
		}
		for _, phrase := range c.never {
			if strings.Contains(body, phrase) {
				t.Errorf("§%s still states the length rule D-074 (c) replaced: %q",
					c.section, phrase)
			}
		}
	}
}
