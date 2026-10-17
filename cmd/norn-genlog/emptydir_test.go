package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Git carries no empty directory, so one the generator leaves behind is in a
// tree it generates and never in a checkout of it: vectors-check passed on the
// Mac, where the stale directory sat in testdata, and failed on the first
// public CI run, which compared a fresh checkout (2026-10-17). Deleting the
// hash tile for other-genesis-missing-tile left tile/0/000.p/ empty.
func TestTheVectorTreeHasNoEmptyDirectory(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		names, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			rel, _ := filepath.Rel(root, path)
			t.Errorf("testdata/vectors/%s is an empty directory, which a checkout does not have", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// removePruned removes a file and every directory that leaves empty, up to
// but not including the root it was served into.
func TestRemovePrunedTakesTheDirectoriesItEmpties(t *testing.T) {
	root := t.TempDir()
	lone := filepath.Join(root, "tile", "0", "000.p", "40")
	kept := filepath.Join(root, "tile", "entries", "000.p", "40")
	for _, path := range []string{lone, kept} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := removePruned(root, lone); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "tile", "0")); !os.IsNotExist(err) {
		t.Errorf("tile/0 is still there after its only file went: %v", err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Errorf("the other tile went with it: %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Errorf("the root went with it: %v", err)
	}
}
