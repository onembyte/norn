package logclient

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// D-078 (4), cold gate run 15's G08: the honest head with one blank line
// before its text is `note` (§7: a note's text lines are non-empty), not the
// `log-signature` of a text that no longer matches its signature. Without the
// blank line it is the honest head and accepted.
func TestAHeadWhoseFirstLineIsBlankIsNote(t *testing.T) {
	checkBlankFirstLineCheckpoint(t)
}

// The manifest walker also requires this case, so removing its shipped file
// cannot leave the framing rule covered only by an in-memory mutation.
func checkBlankFirstLineCheckpoint(t *testing.T) {
	t.Helper()
	const name = "46-blank-first-line"
	var manifest struct {
		Cases []string
		Codes map[string]string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", "cases.json"))), &manifest); err != nil {
		t.Fatal(err)
	}
	found := false
	for i, c := range manifest.Cases {
		if i > 0 && c <= manifest.Cases[i-1] {
			t.Fatal("cases must remain in number order")
		}
		if c == name {
			found = true
		}
	}
	if !found {
		t.Fatal("missing checkpoints-bad/" + name)
	}
	if manifest.Codes[name] != "note" {
		t.Fatalf("manifest code %q, SPEC states note", manifest.Codes[name])
	}
	honest := filepath.Join(vectorRoot(), "served")
	base := readFile(t, filepath.Join(honest, "checkpoint"))
	head := readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", name+".checkpoint"))
	if head != "\n"+base {
		t.Fatal("only one leading line feed before the honest text may differ")
	}
	runFourteenAnswer(t, servedWith(t, honest, head), shippedLogAnchor(t), "note")
	repaired := strings.TrimPrefix(head, "\n")
	if repaired != base {
		t.Fatal("removing the leading line feed must reproduce served/checkpoint exactly")
	}
	runFourteenAnswer(t, servedWith(t, honest, repaired), shippedLogAnchor(t), "accept")
}
