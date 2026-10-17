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
