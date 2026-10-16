package receipt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Step 1 owns the missing line even when the signed body is otherwise sound.
func TestAReceiptWithoutSignatureLinesIsMalformed(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	const name = "no-signature-line.note"
	raw := string(read("receipt-bad/" + name))
	honest := string(read("receipt.note"))
	var without strings.Builder
	for _, line := range strings.SplitAfter(honest, "\n") {
		if !strings.HasPrefix(line, "— ") {
			without.WriteString(line)
		}
	}
	if raw != without.String() {
		t.Fatal("vector must remove only the signature lines")
	}
	var manifest struct {
		Codes map[string]Code
		Rules map[string]struct{ Section, Says string }
	}
	if err := json.Unmarshal(read("receipt-bad/cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	rule := manifest.Rules[name]
	spec, err := os.ReadFile("../../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, _ := strings.Cut(string(spec), "## 7. ")
	section, _, _ = strings.Cut(section, "\n## ")
	if manifest.Codes[name] != Note || rule.Section != "7" || rule.Says == "" || strings.Contains(rule.Says, "\n") || !strings.Contains(section, rule.Says) {
		t.Fatal("manifest must declare note and cite one raw line of §7")
	}
	leaf, origin, deadline := receiptFacts(t, root)
	keys := anchorLogKey(t, root)
	if _, err := Check(honest, keys, origin, leaf, time.Unix(deadline-1, 0)); err != nil {
		t.Fatal(err)
	}
	_, err = Check(raw, keys, origin, leaf, time.Unix(deadline-1, 0))
	if got, _ := CodeOf(err); got != Note {
		t.Fatalf("Go = %q (%v), want note", got, err)
	}
}
