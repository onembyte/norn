package durable

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// The property that makes a crash harmless: the file at `path` is replaced,
// never rewritten in place. A reader that opened the old file keeps reading
// the old bytes, which is the observable half of "the name points at the old
// file or the new one, never at half of either". A write that truncated and
// refilled the same file would hand that reader the new bytes -- and a crash
// between the truncate and the last byte would leave neither.
func TestWriteFileReplacesRatherThanRewrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.evidence")
	if err := os.WriteFile(path, []byte("the old evidence"), 0o644); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	if err := WriteFile(path, []byte("the new evidence, longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	old, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(old) != "the old evidence" {
		t.Errorf("the old file was rewritten in place; a reader saw %q", old)
	}
	now, err := os.ReadFile(path)
	if err != nil || string(now) != "the new evidence, longer" {
		t.Errorf("the path holds %q (%v)", now, err)
	}
}

// Nothing is left behind, and what is there has the mode asked for: a
// temporary file is an implementation detail, not something a reader of the
// directory should ever have to step around.
func TestWriteFileLeavesOnlyTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.evidence")
	if err := WriteFile(path, []byte("evidence"), 0o640); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "b.evidence" {
		t.Errorf("the directory holds %v", entries)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, want 0640", info.Mode().Perm())
	}
}

// A write that cannot finish leaves the file it was replacing exactly as it
// was. Here it cannot even start -- the directory refuses new entries -- and
// an in-place write would not have noticed, because rewriting an existing file
// needs no new entry.
func TestAWriteThatCannotFinishLeavesTheOldFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "c.evidence")
	if err := os.WriteFile(path, []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	if err := WriteFile(path, []byte("lost"), 0o644); err == nil {
		t.Error("a write into a directory that refuses new files claimed success")
	}
	if got, _ := os.ReadFile(path); string(got) != "kept" {
		t.Errorf("the file being replaced now holds %q", got)
	}
}
