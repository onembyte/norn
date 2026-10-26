package specdoc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-077 (1) and (2) decide both the prefix grammar and the trim set, so a
// library's idea of a prefix or whitespace cannot silently replace either.
func TestD077StatesTheGrantGrammarAndTrimSet(t *testing.T) {
	section, ok := load(t).Section("4.0")
	if !ok {
		t.Fatal("§4.0 is missing")
	}
	const paragraph = "**What parses (D-077).** A part is `<address>/<length>` and nothing else, once\nleading and trailing U+0020s are removed and nothing else is. The address is a\ndotted quad — four decimal octets 0–255, none with a leading zero — or an IPv6\naddress as RFC 4291 §2.2 writes it: groups of one to four hexadecimal digits in\neither case, at most one `::`, a dotted quad allowed in place of the last 32\nbits, and no zone. The length is decimal without a leading zero, at most 32\nfor a dotted quad and 128 for IPv6. A bare address, a netmask or hostmask in\nplace of the length, a zone, a leading zero, any other whitespace or any other\nbyte makes the whole label no grant. The grant is each masked prefix in\ncanonical text: the dotted quad, or the IPv6 address in RFC 5952 form with\nevery group in lowercase hexadecimal (an embedded dotted quad is written as\ntwo groups), then `/` and the length. `proven/grant-labels.json` has one case\nper form (cold gate run 14, H1).\n"
	raw, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "`enroll`, as changing any label is.\n\n"+paragraph+"\n### 4.1") {
		t.Error("§4.0 lacks the exact D-077 grant grammar and U+0020 trim paragraph")
	}
	var doc struct {
		Cases []struct{ Label, Says string }
	}
	readJSON(t, filepath.Join(vectorRoot(t), "proven", "grant-labels.json"), &doc)
	index, ok := load(t).Section("12")
	if !ok || !strings.Contains(index.Body, fmt.Sprintf("a `comment` and %d `{label, grant, says}` cases", len(doc.Cases))) {
		t.Error("§12's grant label count does not match the table")
	}
	for _, c := range doc.Cases {
		if c.Says == "" || strings.Contains(c.Says, "\n") || !strings.Contains(section.Body, c.Says) {
			t.Errorf("label %q cites a rule §4.0 does not state on one line: %q", c.Label, c.Says)
		}
	}
}
