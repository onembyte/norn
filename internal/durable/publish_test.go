package durable

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// H4-d: the two `publishKey` twins (keyfile, wgkey; 6.5m-sec-025) fold into
// one exclusive publication here. These are their tests, moved with them: a
// published name is never replaced, and the bytes reach the disk before the
// name does.

func TestPublishNeverReplacesAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	before := []byte("the existing identity")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	err := Publish(path, []byte("a replacement identity"), 0o600)
	if err == nil {
		t.Error("publication replaced a destination created after the existence check")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("the error does not say the file exists: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("the existing bytes were changed")
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatal("publication left a temporary file behind")
	}
}

// The sync seam observes when bytes and names become visible, so the test can
// distinguish flushing the temporary from flushing the published directory.
func TestPublishSyncsTheBytesBeforeTheDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	data := []byte("a new identity")
	calls := 0
	syncFile := func(f *os.File) error {
		calls++
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if info.IsDir() {
			if calls != 2 {
				t.Error("the directory was synced before the bytes")
			}
			files, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				return err
			}
			if len(files) != 1 || files[0].Name() != "key" {
				t.Error("the directory was synced before removing the temporary")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if string(raw) != string(data) {
				t.Error("the published bytes changed")
			}
		} else {
			if calls != 1 {
				t.Error("the bytes were not synced first")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Error("the final name existed before the bytes were synced")
			}
			raw, err := os.ReadFile(f.Name())
			if err != nil {
				return err
			}
			if string(raw) != string(data) {
				t.Error("the temporary was synced before all bytes were written")
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("temporary mode = %o, want 600", info.Mode().Perm())
			}
		}
		return f.Sync()
	}
	if err := PublishWith(path, data, 0o600, syncFile); err != nil {
		t.Fatal(err)
	}
	want := 2 // the file, then the directory
	if runtime.GOOS == "windows" {
		want = 1 // Windows cannot sync a directory handle
	}
	if calls != want {
		t.Fatalf("publication made %d sync calls, want %d", calls, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("published mode = %o, want 600", info.Mode().Perm())
	}
}
