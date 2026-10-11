package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAFinalCommentNeedsALineFeed(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(vectorRoot(), "policies", name+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	bad := read("bad-final-comment-no-lf")
	if bad != read("minimal")+"# note" {
		t.Fatal("not the minimal policy followed by one unterminated comment")
	}
	if _, err := Parse(bad); err == nil {
		t.Fatal("accepted a final comment without LF")
	}
	if _, err := Parse(bad + "\n"); err != nil {
		t.Fatalf("repairing the final LF still refuses the policy: %v", err)
	}
}
