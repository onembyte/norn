package logclient

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/tlogstore"
)

// D-079 (3), from cold gate run 16. tlog-tiles lets a log delete a partial
// tile once the full one is available, and tlogstore does; it lets a client
// fall back to the full tile, and this verifier did not for hash tiles, so a
// node holding an older head could not check it against a Norn log that had
// since filled the tile. The entry-bundle fallback existed and was never
// finished: the full bundle it fetched was then refused for holding more
// entries than the head implies. A verifier that cannot fetch the partial
// path may use the first W hashes, or entries, of the full one; what it uses
// is still compared with the tree it rebuilt, so a corrupt hash inside the
// prefix is `tiles` and one beyond it is nobody's business.
func TestAFullTileAndBundleStandInForDeletedPartialOnes(t *testing.T) {
	inner, entries := loadFixture(t)
	dir := t.TempDir()
	key := logKey(t)
	store, err := tlogstore.Open(dir, "norn/test", key, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(cosign.Append(witnesses(t), cosign.At(cosignedAt)))))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	older := readFile(t, filepath.Join(dir, "checkpoint"))
	// The log grows past 256 entries: the full level-0 tile and the full
	// bundle appear, and the store deletes the partial paths the older head
	// still implies. The appended bytes are never replayed under that head.
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	for _, gone := range []string{"tile/0/000.p/162", "tile/entries/000.p/162"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s should have been deleted when the tile filled: %v", gone, err)
		}
	}
	anchor := Anchor{Anchor: inner, LogKeys: []string{verifierKey(t, key, "norn/test")},
		Policy: policyOver(t, "norn/test", witnessNames, 2)}

	served := servedWith(t, dir, older)
	runFourteenAnswer(t, served, anchor, "accept")

	fullTile := filepath.Join(served, "tile/0/000")
	tile := []byte(readFile(t, fullTile))
	if len(tile) != 256*32 {
		t.Fatalf("the full tile holds %d bytes", len(tile))
	}
	// A corrupt hash among the 162 the older head uses: tiles. One beyond
	// them belongs to a tree this head never claimed, and is not consulted.
	within := append([]byte(nil), tile...)
	within[10*32] ^= 1
	write(t, fullTile, string(within))
	runFourteenAnswer(t, served, anchor, "tiles")
	beyond := append([]byte(nil), tile...)
	beyond[200*32] ^= 1
	write(t, fullTile, string(beyond))
	runFourteenAnswer(t, served, anchor, "accept")
	write(t, fullTile, string(tile))

	// With neither path served, there is nothing to fall back to.
	if err := os.Remove(fullTile); err != nil {
		t.Fatal(err)
	}
	runFourteenAnswer(t, served, anchor, "unserved")
	write(t, fullTile, string(tile))
	if err := os.Remove(filepath.Join(served, "tile/entries/000")); err != nil {
		t.Fatal(err)
	}
	runFourteenAnswer(t, served, anchor, "unserved")
}
