package receipt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
)

func TestTheDeadlineIntegerBoundHasAReSignedVector(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "receipt-bad", "deadline-above-2-63.note"))
	if err != nil {
		t.Fatal(err)
	}
	keys := anchorLogKey(t, root)
	leaf, origin, deadline := receiptFacts(t, root)
	_, err = Check(string(raw), keys, origin, leaf, time.Unix(deadline-1, 0))
	if got, _ := CodeOf(err); got != Deadline {
		t.Fatalf("got %q (%v), want deadline", got, err)
	}
	body, err := note.Verify(string(raw), keys)
	if err != nil {
		t.Fatal(err)
	}
	honestRaw, err := os.ReadFile(filepath.Join(root, "receipt.note"))
	if err != nil {
		t.Fatal(err)
	}
	honest, err := note.Verify(string(honestRaw), keys)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(body, "\n")
	if lines[3] != "9223372036854775808" {
		t.Fatal("deadline is not exactly one past the integer bound")
	}
	lines[3] = strings.Split(honest, "\n")[3]
	if strings.Join(lines, "\n") != honest {
		t.Fatal("the deadline is not the only body fault")
	}
	if _, err := Check(string(honestRaw), keys, origin, leaf, time.Unix(deadline-1, 0)); err != nil {
		t.Fatal(err)
	}
}
