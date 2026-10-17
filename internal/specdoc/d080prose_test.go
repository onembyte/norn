package specdoc

import (
	"strings"
	"testing"
)

// D-080 (1) and (4), row 6.5l-xv-e. §9.1 said what blanks before a policy
// keyword are and nothing of blanks after the last field, so a reader that
// trimmed only the front refused a root-signed policy every implementation
// applied (cold gate run 17, D1). And the 4096-byte cap is §4.0's, on an
// entry's text: a trust file's policy has only MAX_TRUST_BYTES, which no
// sentence said (D5). Keep both sentences where a reader of §9.1 looks.
func TestRunSeventeensPolicyReadingsAreWritten(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("9.1")
	if !ok {
		t.Fatal("§9.1 is missing")
	}
	// Until their vectors ship, §12.1 must say so, or §9.1's table claims
	// vectors it does not have.
	coverage, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	if !strings.Contains(strings.Join(strings.Fields(coverage.Body), " "), "**D-080's rules, until row 6.5l-xv-i ships their vectors.**") {
		t.Error("§12.1 does not list D-080's rules as not yet vectored")
	}
	body := strings.Join(strings.Fields(section.Body), " ")
	for _, want := range []string{
		"| trailing whitespace | spaces and tabs after the last field are not part of it and add no field (D-080) |",
		"Its length is bounded only by `MAX_TRUST_BYTES`",
		"can never be republished as a `policy` entry (D-080)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("§9.1 does not say %q", want)
		}
	}
}

// D-080 (2), row 6.5l-xv-f. §11.1 step 1 said "this network's log key",
// singular, where §7, §8.1 and §10 name the trust file's key and every one a
// replayed state has published; after a rotation, one reader proved a fork
// that another refused (cold gate run 17, D2). Step 1 names §9.4's set, and
// the opening says what the trust-file-only reader answers, as §8 does for a
// bundle.
func TestEvidenceIsCheckedUnderTheKeysTheReaderTrusts(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("11.1")
	if !ok {
		t.Fatal("§11.1 is missing")
	}
	body := strings.Join(strings.Fields(section.Body), " ")
	for _, want := range []string{
		"the log keys the reader trusts (§9.4: the trust file's, plus every `log_key` of a state it has accepted)",
		"one holding only the older trust file answers `held`, which is the truth",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("§11.1 does not say %q", want)
		}
	}
	if strings.Contains(body, "this network's origin, this network's log key, and a satisfied witness quorum") {
		t.Error("§11.1 step 1 still names one log key")
	}
}

// D-080 (3) with D10, row 6.5l-xv-g. §6 let a verifier fall back to the full
// tile ("MAY") where §10.1 step 1 and grown-log/ already required it, and did
// not say the full file must itself be well formed (cold gate run 17, D3 and
// D10). §6 says both, and §10.1's steps 8 and 12 say what each code means for
// a stand-in.
func TestAStandInFullFileIsAFullFile(t *testing.T) {
	doc := load(t)
	for _, c := range []struct{ section, want string }{
		{"6", "a verifier that cannot fetch `tile/<L>/<N>.p/<W>` MUST fetch `tile/<L>/<N>` before it answers `unserved`"},
		{"6", "the file it fetches must itself be a well-formed full tile or bundle — exactly 32 × 256 bytes, or exactly 256 frames"},
		{"10.1", "A full tile standing in for a deleted partial one (§6) is a full tile: 32 × 256 bytes, of which the first 32 × `W` are compared; a longer or shorter one is `tiles` (step 12)"},
		{"10.1", "A full bundle standing in for a deleted partial one (§6) holds exactly 256 frames, of which the first `W` are the head's; any other count is `entries` (step 8)"},
	} {
		section, ok := doc.Section(c.section)
		if !ok {
			t.Fatalf("§%s is missing", c.section)
		}
		if !strings.Contains(strings.Join(strings.Fields(section.Body), " "), c.want) {
			t.Errorf("§%s does not say %q", c.section, c.want)
		}
	}
	six, _ := doc.Section("6")
	if strings.Contains(strings.Join(strings.Fields(six.Body), " "), "MAY fetch `tile/<L>/<N>` and use its first `W` hashes") {
		t.Error("§6 still says MAY")
	}
}

// D-080 (5) with D7, row 6.5l-xv-h. "Decodes under §16.1" did not say what
// decoding covers, and readers split on whether it checks the request's
// signature and network (cold gate run 17, D6); nothing bounded `entry`, so
// an oversize one went to step 4 as `binding` in Go (D7). §8.1 says what
// decoding is and that the entry is an entry, and §10.1's step 1 names it.
func TestABundlesEntryIsAnEntryAndDecodingIsStructure(t *testing.T) {
	doc := load(t)
	for _, c := range []struct{ section, want string }{
		{"8.1", "| `entry` | bytes | the entry itself, so the bundle stands alone; at most `MAX_ENTRY_BYTES` (§4.0), like any entry, and a longer one is `bundle` (D-080) |"},
		{"8.1", "Decoding here is the request's structure and field rules, §3.1's point admission included; its signature and network are not part of it"},
		{"8.1", "The entry itself must decode under §4.0's profile and §4.1's envelope — version 1, a text `t`, a map `body` — or it names no device"},
		{"10.1", "or an `entry` longer than `MAX_ENTRY_BYTES` (D-080)"},
	} {
		section, ok := doc.Section(c.section)
		if !ok {
			t.Fatalf("§%s is missing", c.section)
		}
		if !strings.Contains(strings.Join(strings.Fields(section.Body), " "), c.want) {
			t.Errorf("§%s does not say %q", c.section, c.want)
		}
	}
}
