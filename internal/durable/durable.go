// Package durable writes files that must survive the machine stopping halfway.
//
// Most of what Norn writes can be lost to a crash and rebuilt on the next
// cycle. Fork evidence cannot: its presence is the freeze (§11), and a freeze
// that a power cut can tear is a freeze an attacker who can pull a plug can
// lift. So such a file is written beside its destination, flushed to the disk,
// renamed over the destination, and the rename itself flushed -- after which
// the name points at the old bytes or the new ones, never at half of either,
// and whichever it points at is on the disk rather than in a cache.
package durable

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// WriteFile replaces path with data, durably.
//
// The temporary file starts with a dot and ends in `.tmp`, so a reader that
// globs for a suffix such as `*.evidence` never mistakes a write that was cut
// short for a finished one.
func WriteFile(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("durable: %w", err)
	}
	defer func() {
		if err != nil {
			temp.Close()
			os.Remove(temp.Name())
		}
	}()
	if _, err = temp.Write(data); err != nil {
		return fmt.Errorf("durable: %w", err)
	}
	if err = temp.Chmod(perm); err != nil {
		return fmt.Errorf("durable: %w", err)
	}
	// The bytes reach the disk before the name does, or a crash just after
	// the rename could leave the name pointing at an empty file.
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("durable: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("durable: %w", err)
	}
	if err = os.Rename(temp.Name(), path); err != nil {
		return fmt.Errorf("durable: %w", err)
	}
	return syncDir(dir)
}

// syncDir flushes a directory's entries, which is what makes a rename
// survive a power cut. Windows cannot open a directory for writing and
// orders its metadata itself, so there it is skipped.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("durable: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("durable: syncing %s: %w", dir, err)
	}
	return nil
}
