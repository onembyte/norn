package logclient

import (
	"path/filepath"
	"testing"
)

// D-080 (3), row 6.5l-xv-g. A full tile or bundle served in place of a
// deleted partial one is a file at a full path, so it must be a full file:
// 8192 bytes, or 256 frames. Only then are its first W hashes or entries the
// ones the older head implies. checkTiles compared the first W hashes of
// whatever came back, so a tile two bytes too long, or cut to the head's 162
// hashes, passed; bundleEntries already required the exact count (cold gate
// run 17, D3). Each case changes one file of grown-log/ beside the sound head.
func TestAFullFileStandingInForAPartialOneMustItselfBeFull(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "grown-log")
	head := readFile(t, filepath.Join(dir, "checkpoint"))
	tile := readFile(t, filepath.Join(dir, "tile/0/000"))
	bundle := readFile(t, filepath.Join(dir, "tile/entries/000"))
	if len(tile) != 8192 {
		t.Fatalf("grown-log's full tile is %d bytes", len(tile))
	}
	for _, c := range []struct {
		name, path, body, want string
	}{
		{"as shipped", "", "", "accept"},
		{"full tile with two trailing bytes", "tile/0/000", tile + "\x00\x00", "tiles"},
		{"full tile cut to the head's 162 hashes", "tile/0/000", tile[:162*32], "tiles"},
		{"full bundle with two trailing bytes", "tile/entries/000", bundle + "\x00\x00", "entries"},
	} {
		t.Run(c.name, func(t *testing.T) {
			served := servedWith(t, dir, head)
			if c.path != "" {
				write(t, filepath.Join(served, c.path), c.body)
			}
			runFourteenAnswer(t, served, shippedLogAnchor(t), c.want)
		})
	}
}
