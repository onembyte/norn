package logclient

import (
	"path/filepath"
	"testing"
)

// D-078 (4), cold gate run 15's G08: the honest head with one blank line
// before its text is `note` (§7: a note's text lines are non-empty), not the
// `log-signature` of a text that no longer matches its signature. Without the
// blank line it is the honest head and accepted.
func TestAHeadWhoseFirstLineIsBlankIsNote(t *testing.T) {
	honest := filepath.Join(vectorRoot(), "served")
	base := readFile(t, filepath.Join(honest, "checkpoint"))
	runFourteenAnswer(t, servedWith(t, honest, "\n"+base), shippedLogAnchor(t), "note")
	runFourteenAnswer(t, servedWith(t, honest, base), shippedLogAnchor(t), "accept")
}
