package mirror

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/tlog"
)

// Every append used to leave another partial behind, including at higher
// levels. The previous checkpoint's exact paths must still serve a peer that
// read it just before the new checkpoint arrived.
func TestOnlyTheCurrentAndPreviousHeadsPartialsRemain(t *testing.T) {
	dir := t.TempDir()
	entries := make([][]byte, 2*tlog.TileWidth+1)
	for i := range entries {
		entries[i] = []byte(fmt.Sprintf("entry %d", i))
	}
	for n := 1; n <= len(entries); n++ {
		adopt(t, dir, entries[:n])
		want := headPaths(t, entries[:n], false)
		for path := range headPaths(t, entries[:n-1], true) {
			want[path] = true
		}
		got := tileFiles(t, dir)
		for path := range got {
			if !want[path] {
				t.Fatalf("head %d retained obsolete path %s", n, path)
			}
		}
		for path := range want {
			if !got[path] {
				t.Fatalf("head %d lost required path %s", n, path)
			}
		}
	}
}

func TestCleanupPreservesFullTilesAndForeignFiles(t *testing.T) {
	dir := t.TempDir()
	foreign := []string{
		"operator.txt", "tile/README", "tile/0/999", "tile/entries/999",
		"tile/0/999.p/0", "tile/0/999.p/256", "tile/0/999.p/01",
		"tile/00/999.p/1", "tile/other/999.p/1", "tile/0/99.p/1",
		"tile/0/x000/999.p/1", "tile/0/x001/99.p/1",
		"tile/0/999.p/1.extra", "tile/entries/999.p/operator.txt",
		"tile/0/x999/x999/x999/x999/x999/x999/999.p/1",
	}
	for _, path := range foreign {
		put(t, dir, path, []byte("operator data"))
	}
	// Canonical grouped paths are eligible even when no adopted head needed
	// them, as happens after an interrupted write of a larger head.
	obsolete := []string{tlog.TilePath(2, 1234067, 17), tlog.EntryBundlePath(1000, 2)}
	for _, path := range obsolete {
		put(t, dir, path, []byte("obsolete partial"))
	}
	entries := make([][]byte, tlog.TileWidth+2)
	adopt(t, dir, entries[:tlog.TileWidth+1])
	adopt(t, dir, entries)
	for _, path := range foreign {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil || string(raw) != "operator data" {
			t.Errorf("cleanup changed foreign or full path %s: %q (%v)", path, raw, err)
		}
	}
	for _, path := range obsolete {
		if _, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(path))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("obsolete canonical partial %s remains: %v", path, err)
		}
	}
}

func TestCleanupDoesNotFollowSymlinksInTheTileTree(t *testing.T) {
	for _, link := range []string{"tile", "tile/2", "tile/0/x001", "tile/0/999.p", "tile/0/999.p/1"} {
		t.Run(link, func(t *testing.T) {
			dir, outside := t.TempDir(), t.TempDir()
			adopt(t, dir, [][]byte{[]byte("first")})
			// The root-tile case is installed at the checkpoint seam, after
			// writes, so this test observes deletion rather than publication.
			for _, path := range []string{"1", "999.p/1", "0/999.p/1"} {
				put(t, outside, path, []byte("outside"))
			}
			was := writeFile
			writeFile = func(path string, data []byte, perm os.FileMode) error {
				if err := was(path, data, perm); err != nil {
					return err
				}
				if filepath.Base(path) == "checkpoint" {
					if link == "tile" {
						if err := os.Rename(filepath.Join(dir, "tile"), filepath.Join(dir, "saved-tiles")); err != nil {
							return err
						}
					}
					target := filepath.Join(dir, filepath.FromSlash(link))
					if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
						return err
					}
					return os.Symlink(outside, target)
				}
				return nil
			}
			t.Cleanup(func() { writeFile = was })
			adopt(t, dir, [][]byte{[]byte("first"), []byte("second")})
			for _, path := range []string{"1", "999.p/1", "0/999.p/1"} {
				raw, err := os.ReadFile(filepath.Join(outside, filepath.FromSlash(path)))
				if err != nil || string(raw) != "outside" {
					t.Errorf("cleanup followed %s: %q (%v)", link, raw, err)
				}
			}
		})
	}
}

// A verifier has already read the old checkpoint, but fetches its data from
// the live mirror after the next adoption, including at a full-tile boundary.
type checkpointReader struct {
	logclient.Fetcher
	signed string
}

func (f checkpointReader) Fetch(path string) ([]byte, error) {
	if path == "checkpoint" {
		return []byte(f.signed), nil
	}
	return f.Fetcher.Fetch(path)
}

func TestAPeerStillVerifiesThePreviousHeadAfterANewWrite(t *testing.T) {
	large, err := logclient.Verify(logclient.Dir(filepath.Join(vectors(), "served-large")), anchorOf(t))
	if err != nil {
		t.Fatal(err)
	}
	anchor := anchorOf(t)
	anchor.Policy = "quorum none\n"
	for _, sizes := range [][2]int{{255, 256}, {256, 257}, {257, 258}, {260, 280}} {
		n, next := sizes[0], sizes[1]
		t.Run(fmt.Sprintf("%d-to-%d", n, next), func(t *testing.T) {
			dir := t.TempDir()
			adopt(t, dir, large.Served[:n])
			old, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
			if err != nil {
				t.Fatal(err)
			}
			adopt(t, dir, large.Served[:next])
			back, err := logclient.Verify(checkpointReader{logclient.Dir(dir), string(old)}, anchor)
			if err != nil {
				t.Fatalf("the previous head no longer verifies: %v", err)
			}
			if back.Checkpoint.Size != int64(n) {
				t.Fatalf("verified head %d, want %d", back.Checkpoint.Size, n)
			}
		})
	}
}

func TestACrashAroundCheckpointPublicationLeavesAVerifiableMirror(t *testing.T) {
	result := verified(t)
	anchor := anchorOf(t)
	anchor.Policy = "quorum none\n"
	for _, published := range []bool{false, true} {
		t.Run(fmt.Sprint(published), func(t *testing.T) {
			dir := t.TempDir()
			n := len(result.Served)
			adopt(t, dir, result.Served[:n-2])
			adopt(t, dir, result.Served[:n-1])
			stale := tlog.TilePath(0, 0, n-2)
			crash := errors.New("simulated crash at checkpoint publication")
			was := writeFile
			writeFile = func(path string, data []byte, perm os.FileMode) error {
				if filepath.Base(path) != "checkpoint" {
					return was(path, data, perm)
				}
				if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(stale))); err != nil {
					t.Errorf("cleanup ran before the checkpoint was durable: %v", err)
				}
				if published {
					if err := was(path, data, perm); err != nil {
						return err
					}
				}
				return crash
			}
			t.Cleanup(func() { writeFile = was })
			err := Write(dir, result.Checkpoint, result.SignedCheckpoint, result.Served)
			if !errors.Is(err, crash) {
				t.Fatalf("write did not stop at the crash: %v", err)
			}
			back, err := logclient.Verify(logclient.Dir(dir), anchor)
			if err != nil {
				t.Fatalf("the mirror does not verify after a crash: %v", err)
			}
			want := int64(n - 1)
			if published {
				want = int64(n)
			}
			if back.Checkpoint.Size != want {
				t.Fatalf("crash left head %d, want %d", back.Checkpoint.Size, want)
			}
			if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(stale))); err != nil {
				t.Fatalf("the interrupted cleanup did not leave extra files: %v", err)
			}
		})
	}
}

func TestCleanupReturnsRemovalErrorsAfterPublishingTheCheckpoint(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	stale := tlog.TilePath(0, 999, 1)
	put(t, dir, stale, []byte("obsolete"))
	parent := filepath.Dir(filepath.Join(dir, filepath.FromSlash(stale)))
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0o755) })
	entries := [][]byte{[]byte("first")}
	signed := headFor(t, entries)
	if err := Write(dir, headOf(t, entries), signed, entries); err == nil {
		t.Fatal("a removal error was ignored")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil || string(raw) != signed {
		t.Fatalf("cleanup ran before checkpoint publication: %v", err)
	}
}

func adopt(t *testing.T, dir string, entries [][]byte) {
	t.Helper()
	if err := Write(dir, headOf(t, entries), headFor(t, entries), entries); err != nil {
		t.Fatal(err)
	}
}

func put(t *testing.T, dir, rel string, data []byte) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func headPaths(t *testing.T, entries [][]byte, partialOnly bool) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for index := int64(0); index*tlog.TileWidth < int64(len(entries)); index++ {
		width := min(tlog.TileWidth, len(entries)-int(index)*tlog.TileWidth)
		if !partialOnly || width < tlog.TileWidth {
			out[tlog.EntryBundlePath(index, width)] = true
		}
	}
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	tiles, err := tree.Tiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, tile := range tiles {
		if !partialOnly || tile.Width < tlog.TileWidth {
			out[tile.Path()] = true
		}
	}
	return out
}

func tileFiles(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(dir, "tile"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			out[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A file can disappear after WalkDir lists it. Missing is harmless; other
// removal failures must remain observable to the caller.
func TestAFileThatDisappearsDuringCleanupIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	stale := tlog.EntryBundlePath(999, 1)
	put(t, dir, stale, []byte("obsolete"))
	was := removeFile
	called := false
	removeFile = func(root *os.Root, path string) error {
		called = true
		if err := was(root, path); err != nil {
			return err
		}
		return was(root, path)
	}
	t.Cleanup(func() { removeFile = was })
	adopt(t, dir, [][]byte{[]byte("first")})
	if !called {
		t.Fatal("cleanup never exercised the missing-file race")
	}
}
