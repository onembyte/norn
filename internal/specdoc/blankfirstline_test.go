package specdoc

import (
	"strings"
	"testing"
)

// D-078 (4), cold gate run 15's L2: §7 said a note's text lines are non-empty
// and never said what a note whose first line is blank is. Keep the answer
// where a reader learns the framing.
func TestD078ANoteWhoseFirstLineIsBlankIsNote(t *testing.T) {
	doc := load(t)
	s, ok := doc.Section("7")
	if !ok {
		t.Fatal("§7 is missing")
	}
	body := strings.Join(strings.Fields(s.Body), " ")
	const want = "The text is at least one line: a note whose first line is blank has an empty first text line and is `note`, refused before any signature is checked (D-078)"
	if !strings.Contains(body, want) {
		t.Errorf("§7 lacks %q", want)
	}
}
