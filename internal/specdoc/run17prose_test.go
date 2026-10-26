package specdoc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cold gate run 17's prose findings (row 6.5l-xv-b). D4: §11.1 step 4 says a
// `split` of 0 carries an all-zero `split_root`, and no code named the file
// that breaks it. D8: a proof hash of the wrong length in a bundle, `bundle`
// or `inclusion`. D9: a short evidence file declaring a huge length, `cbor` or
// `oversize`. D12: the preamble let the reused standards win over every rule
// this document narrows, outside §7 and §10. D11: §12.1 claimed the 32-byte
// `device_pk` and the trust file's witness names were pinned, miscounted
// `receipt-bad/`, kept a bullet that named no rule, and let
// `request-undecodable` stand for a rule its label cannot isolate. Keep each
// correction; refuse the old words. D10 waits for D3's decision (6.5l-xv-c).
func TestRunSeventeensProseFindingsAreFixed(t *testing.T) {
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
		{"D12 a narrower rule governs", "",
			"Where this document states a rule more narrowly than one of them — a profile, a closed set, an exact count — its rule governs",
			"where they conflict with this document, they win, with one exception"},
		{"D4 split 0 with a root", "11.1",
			"`split` is 0 with a `split_root` that is not all zero (step 4)",
			""},
		{"D9 oversize is the file's own length", "11.1",
			"It is the file's own length: a short file whose CBOR declares more than it holds is `cbor`, not `oversize`",
			""},
		{"D8 a short proof hash", "10.1",
			"or a `proof` element that is not exactly 32 bytes, as §8.1 types it",
			""},
		{"D11 device_pk is refused, never isolated", "12.1",
			"§3.1's point admission refuses a 31-byte key at the same step",
			"So the rule is pinned, through the entry's code."},
		{"D11 receipt count includes the new framing case", "12.1",
			"**23 `receipt-bad/` cases**",
			"**19 `receipt-bad/` cases**"},
		{"D11 the trust file's witness names", "12.1",
			"so neither isolates it (cold gate run 17, D11)",
			""},
		{"D11 request-undecodable shows the rule only by its reason", "12.1",
			"so it shows the rule only to a reader that reports why",
			""},
		{"D11 run 17's unvectored rules are named", "12.1",
			"**Rules stated plainly that no vector holds yet (cold gate run 17, D11).**",
			""},
		{"D11 run 16's bullet says what became of its rules", "12.1",
			"Every rule run 16 listed here is now vectored",
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
