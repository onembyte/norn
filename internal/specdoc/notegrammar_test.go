package specdoc

import (
	"os"
	"strings"
	"testing"
)

// D-077's owner supplied exact passages. Keep their bytes and their placement,
// since a nearby paraphrase would leave another reader choosing the grammar.
func TestTheDecidedNoteGrammarPassagesAreExact(t *testing.T) {
	raw, err := os.ReadFile("../../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, tc := range []struct{ name, want, stale string }{
		{"The timestamp is bounded before verification", `    timestamp is an unsigned 64-bit **big-endian** count of seconds since the
    Unix epoch, at most 2⁶³−1 — the bound on every decimal line, and it is one
    in the cosigned message below (D-077); a listed witness's line whose
    timestamp is above it fails that witness's check, ` + "`" + `cosignature` + "`" + `, before its
    signature is verified. It is the only timestamp in the artifact: §5.3's ` + "`" + `T` + "`" + ` is
`, `    timestamp is an unsigned 64-bit **big-endian** count of seconds since the
    Unix epoch, and it is the only timestamp in the artifact: §5.3's ` + "`" + `T` + "`" + ` is
`},
		{"The whole note excludes controls", `- The signed text and every signature line MUST be valid UTF-8, and MUST NOT contain an ASCII control character below U+0020 other than the line feeds that end lines — a carriage return included — as ` + "`" + `c2sp.org/signed-note` + "`" + ` requires. A note that is not is malformed note framing, refused as ` + "`" + `note` + "`" + ` before any key is looked for: a reader that decodes the text before it verifies must see the bytes this one does (D-074 c, D-077).
`, `- The signed text and every signature line MUST be valid UTF-8. A note that is not is malformed note framing, refused as ` + "`" + `note` + "`" + ` before any key is looked for: a reader that decodes the text before it verifies must see the bytes this one does (D-074 c).
`},
		{"Signature names have the complete grammar", `- **A signature line's name** is one or more characters, none of them ` + "`" + `+` + "`" + ` and
  none a Unicode white-space character — U+0009–U+000D, U+0020, U+0085, U+00A0,
  U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F and U+3000, the whole
  property, written out so that no implementation consults its own table — as
  ` + "`" + `c2sp.org/signed-note` + "`" + ` requires. A line whose name is empty or breaks this
  rule does not frame, and the note is ` + "`" + `note` + "`" + `. "Ignored" is said only of a line
  that has framed: a well-formed line whose name and key id match no trusted
  key (D-077).
- The decoded payload is **exactly** that length for the matched key, never a
`, ``},
		{"Strangers follow the signature name grammar", `  is already inside it. The grammar is a verifier key's. A signature line's
  name follows the looser rule above — any characters but ` + "`" + `+` + "`" + ` and white space —
  so a stranger's well-formed line under a name outside this grammar, a
  non-ASCII one say, is still ignored (` + "`" + `served-stranger-name/` + "`" + `). The
`, `  is already inside it. The grammar is a verifier key's; a signature line's
  name is only matched against verifier keys, so a stranger's line under any
  other name is still ignored, as above. The
`},
		{"Framing failures include controls and names", `text or a line that is not UTF-8 or carries an ASCII control character other than a line-ending LF, a signature line whose name is empty or holds ` + "`" + `+` + "`" + ` or white space,`, `text or a line that is not UTF-8,`},
		{"Witness failures include the timestamp bound", `(` + "`" + `checkpoints-bad/28-witness-key-other-algorithm-length` + "`" + `) or whose timestamp is above 2⁶³−1 (§7, D-077) |`, `(` + "`" + `checkpoints-bad/28-witness-key-other-algorithm-length` + "`" + `) |`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(text, tc.want) != 1 {
				t.Error("the exact decided passage is missing or repeated")
			}
			if tc.stale != "" && strings.Contains(text, tc.stale) {
				t.Error("the replaced passage remains")
			}
		})
	}
}
