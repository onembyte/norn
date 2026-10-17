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
