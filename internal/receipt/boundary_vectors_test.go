package receipt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
)

func checkReceiptBoundaries(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	keys := anchorLogKey(t, root)
	leaf, origin, deadline := receiptFacts(t, root)
	honestRaw, err := os.ReadFile(filepath.Join(root, "receipt.note"))
	if err != nil {
		t.Fatal(err)
	}
	honest, err := note.Verify(string(honestRaw), keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fifth-line.note", "origin-case-changed.note"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, "receipt-bad", name))
			if err != nil {
				t.Fatal(err)
			}
			_, err = Check(string(raw), keys, origin, leaf, time.Unix(deadline-1, 0))
			want := ReceiptFormat
			if name == "origin-case-changed.note" {
				want = Origin
			}
			if got, _ := CodeOf(err); got != want {
				t.Fatalf("got %q (%v), want %q", got, err, want)
			}
			text, err := note.Verify(string(raw), keys)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
			if name == "fifth-line.note" {
				if len(lines) != 5 {
					t.Fatal("expected five signed lines")
				}
				lines = lines[:4]
			} else {
				if lines[1] == origin || !strings.EqualFold(lines[1], origin) {
					t.Fatal("origin must differ only in case")
				}
				lines[1] = origin
			}
			if strings.Join(lines, "\n")+"\n" != honest {
				t.Fatal("repair leaves another body fault")
			}
			if _, err := Check(string(honestRaw), keys, origin, leaf, time.Unix(deadline-1, 0)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
