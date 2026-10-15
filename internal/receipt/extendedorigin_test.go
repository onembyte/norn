package receipt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
)

func TestAnExtendedReceiptOriginIsOriginAndItsHonestTwinAccepts(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var m struct{ Codes map[string]Code }
	if err := json.Unmarshal(read("receipt-bad/cases.json"), &m); err != nil {
		t.Fatal(err)
	}
	if m.Codes["origin-extended.note"] != Origin {
		t.Error("receipt-bad/origin-extended.note must be coded origin")
	}
	bad := string(read("receipt-bad/origin-extended.note"))
	good := string(read("receipt.note"))
	keys := anchorLogKey(t, root)
	leaf, origin, deadline := receiptFacts(t, root)
	badText, err := note.Verify(bad, keys)
	if err != nil {
		t.Fatal(err)
	}
	goodText, err := note.Verify(good, keys)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Replace(badText, "\n"+origin+"x\n", "\n"+origin+"\n", 1) != goodText {
		t.Fatal("only one appended origin character may differ in signed text")
	}
	if _, err := Check(bad, keys, origin, leaf, time.Unix(deadline-1, 0)); err == nil {
		t.Fatal("Go accepts extended origin; SPEC states origin")
	} else if code, _ := CodeOf(err); code != Origin {
		t.Fatalf("Go answers %q (%v), SPEC states origin", code, err)
	}
	if _, err := Check(good, keys, origin, leaf, time.Unix(deadline-1, 0)); err != nil {
		t.Fatal(err)
	}
}
