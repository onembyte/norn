package logclient

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// Every malformed full file stands beside the unmodified full fallback.
func TestD080ShippedStandInFilesMustBeFull(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "grown-log")
	var m struct {
		Cases []servedNegative
		Codes map[string]string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &m); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, path, want string }{
		{"full-tile-trailing-bytes", "tile/0/000", "tiles"},
		{"full-tile-truncated", "tile/0/000", "tiles"},
		{"full-bundle-trailing-bytes", "tile/entries/000", "entries"},
	} {
		t.Run(c.name, func(t *testing.T) {
			runFourteenAnswer(t, dir, shippedLogAnchor(t), "accept")
			var found *servedNegative
			for i := range m.Cases {
				if m.Cases[i].Name == c.name {
					if found != nil {
						t.Fatal("duplicate case")
					}
					found = &m.Cases[i]
				}
			}
			if found == nil || m.Codes[c.name] != c.want {
				t.Fatal("case must be shipped with code " + c.want)
			}
			if found.Path != c.path || found.File != c.name+".bin" || found.Remove {
				t.Fatal("replacement must name the full path and its file")
			}
			original := readFile(t, filepath.Join(dir, c.path))
			changed := readFile(t, filepath.Join(dir, found.File))
			want := original + "\x00\x00"
			if c.name == "full-tile-truncated" {
				want = original[:162*32]
			}
			if changed != want {
				t.Fatal("only the specified length mutation may change")
			}
			copy := servedWith(t, dir, readFile(t, filepath.Join(dir, "checkpoint")))
			write(t, filepath.Join(copy, c.path), changed)
			runFourteenAnswer(t, copy, shippedLogAnchor(t), c.want)
			t.Logf("grown-log/%s: %s; sound twin: accept", c.name, c.want)
		})
	}
}
