package specdoc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cold gate run 16's prose findings (row 6.5l-xiv-b). M1: §4.0's restated
// profile never said that `false` and `true` are the single bytes 0xf4 and
// 0xf5, though RFC 8949 §3.3 already makes 0xf8 0x14 and 0xf8 0x15 not
// well-formed and every implementation refuses them. M3: the preamble sent
// proof *verification* to RFC 6962 §2.1.1 and §2.1.2, which define the proofs;
// the verifiers are RFC 9162's, and a padded list is not the proof. L1: entry
// 0 recorded "the duplicate key", singular, after D-078 made two. L2: "listed
// witness" once a `policy` entry has dropped one. L4, L5, L6, L8: §12.1's
// account of its holes. L7: item 3 never said `A` is a valid point. L9: §6
// counted three byte ranges where there are two. Keep each correction; refuse
// the old words.
func TestRunSixteensProseFindingsAreFixed(t *testing.T) {
	doc := load(t)
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	raw, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	preamble, _, _ := strings.Cut(string(raw), "\n## 1.")
	for _, c := range []struct {
		name, section, want, stale string
	}{
		{"M3 RFC 9162 verifies the proofs", "",
			"RFC 9162 §2.1.3.2 and RFC 9162 §2.1.4.2 — verifying an inclusion proof and verifying consistency between two tree heads",
			"inclusion-proof verification, used by §8.1"},
		{"M3 a padded list is not the proof", "",
			"A list with more or fewer hashes than the procedure consumes is not the proof",
			"consistency-proof verification, used by §11.1"},
		{"M3 the bundle's proof", "8.1",
			"verified per RFC 9162 §2.1.3.2: exactly the hashes that procedure consumes",
			""},
		{"M3 the bundle's inclusion code", "10.1",
			"or the proof carries more or fewer hashes than RFC 9162 §2.1.3.2 consumes",
			""},
		{"M3 the evidence's proof", "11.1",
			"verified per RFC 9162 §2.1.4.2, and a list with more or fewer hashes than that procedure consumes does not chain",
			""},
		{"M1 the single bytes", "4.0",
			"`true` (21) of major type 7, as the single bytes `0xf4` and `0xf5` — and **nothing else**",
			""},
		{"M1 the two-byte form is not well-formed", "4.0",
			"`0xf8` followed by any byte below 32 — `0xf8 0x14` and `0xf8 0x15` included — which RFC 8949 §3.3 makes not well-formed",
			""},
		{"L1 entry 0 joins both seen sets", "5.1",
			"1. Its `entry_hash` joins §5.1 step 1's first seen set, and when step 8 applies it, its `content_hash` joins the second (D-078).",
			"1. The duplicate key of §5.1 step 1 is recorded as seen."},
		{"L2 listed means named by the policy in force", "10.1",
			"listed meaning named by the policy in force (§9.4), not a witness a `policy` entry has dropped that the trust file still lists",
			""},
		{"L7 A is a valid point", "3.1",
			"verifies under a key `A` — itself a valid point, since item 2 admits no other — over a message",
			""},
		{"L9 two byte ranges", "6",
			"which is also §7's *signed text* and stops one `0x0A` earlier: those are two different byte ranges",
			"those are three different byte ranges"},
		{"L4 the trust file's log_key is the exception", "12.1",
			"The exception is a trust file's `log_key`: both implementations refuse a small-order one, and no file in `trust-bad/` holds it yet (cold gate run 16, L4)",
			"is vectored at every admission point item 2 names and executed"},
		{"L5 the policy cap has no vector", "12.1",
			"`bad-text-too-long` is the same shape for `note`'s 4096-byte cap: 4097 bytes, 2049 characters. `policy`'s cap has no vector yet (cold gate run 16, L5)",
			"is the same shape for `note` and `policy`'s 4096-byte cap"},
		{"L6 device_pk is pinned through log/81's code", "12.1",
			"`log/81-bad-pk-length` embeds such a request and is `decode`, where a reader without the rule decodes the request and answers `no-device-sig`",
			"No construction separates the two, so the rule is refused-but-not-pinned"},
		{"L8 the rules no vector holds yet", "12.1",
			"**Rules stated plainly that no vector holds yet (cold gate run 16, L8).**",
			""},
	} {
		t.Run(c.name, func(t *testing.T) {
			body, where := preamble, "the preamble"
			if c.section != "" {
				s, ok := doc.Section(c.section)
				if !ok {
					t.Fatalf("§%s is missing", c.section)
				}
				body, where = s.Body, "§"+c.section
			}
			body = norm(body)
			if !strings.Contains(body, norm(c.want)) {
				t.Errorf("%s is missing %q", where, c.want)
			}
			if c.stale != "" && strings.Contains(body, norm(c.stale)) {
				t.Errorf("%s still says %q", where, c.stale)
			}
		})
	}
}
