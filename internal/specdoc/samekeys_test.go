package specdoc

import (
	"strings"
	"testing"
)

// D-074 (d). §9.1 said a trust file's policy names the listed witnesses "with
// the same keys" and never said which comparison, while its grammar table
// compares keys by parsed public key -- a rule written for duplicates. Both
// implementations compare the whole verifier-key text, the stricter reading,
// and the right one: §10 matches a cosignature line by name and key id. These
// are the sentences that say so; the duplicate rule stays as it is.
func TestTheSameKeysAreTheSameVerifierKeyText(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("9.1")
	if !ok {
		t.Fatal("§9.1 is missing")
	}
	body := strings.Join(strings.Fields(section.Body), " ")
	for _, phrase := range []string{
		"the same verifier key — name, algorithm and public key — compared as canonical text",
		"a policy that names a listed witness's public key under another key name names a different key",
		"`trust-bad/48-policy-witness-key-renamed`",
		"a `log` line is compared the same way",
		"Keys are compared by their parsed underlying public key",
	} {
		if !strings.Contains(body, phrase) {
			t.Errorf("§9.1 does not state D-074 (d): missing %q", phrase)
		}
	}
}
