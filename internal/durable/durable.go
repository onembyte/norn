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
	"errors"
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

// ErrExists reports a publication refused because the name is taken.
var ErrExists = errors.New("already exists")

// Publish writes data under a name that must not exist yet, durably, and
// never replaces one that does.
//
// WriteFile replaces: that is what a mirror or a clock file wants. A key file
// is the opposite case -- an identity, generated once -- and the two
// `publishKey` twins in keyfile and wgkey (6.5m-sec-025) were this function
// written twice. The bytes are flushed before the name exists, the name is
// made by an exclusive link so a file that appeared after any earlier check
// is never overwritten, and the directory is flushed after the temporary is
// gone, so both name changes survive together with the already-synced bytes.
func Publish(path string, data []byte, perm os.FileMode) error {
	return PublishWith(path, data, perm, (*os.File).Sync)
}

// PublishWith is Publish with the sync call replaceable, so a test can watch
// the order in which bytes and names reach the disk.
func PublishWith(path string, data []byte, perm os.FileMode, sync func(*os.File) error) error {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("durable: %w", err)
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(perm); err != nil {
		temp.Close()
		return fmt.Errorf("durable: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("durable: %w", err)
	}
	// Flush the bytes before publishing a name that another process can read.
	if err := sync(temp); err != nil {
		temp.Close()
		return fmt.Errorf("durable: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("durable: %w", err)
	}
	// Linking is exclusive: a name created after any earlier check is never
	// replaced.
	if err := os.Link(temp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("durable: %s %w", path, ErrExists)
		}
		return fmt.Errorf("durable: %w", err)
	}
	// Remove the temporary before flushing the directory, so both name changes
	// survive together with the already-synced bytes.
	if err := os.Remove(temp.Name()); err != nil {
		return fmt.Errorf("durable: %w", err)
	}
	// Windows cannot open a directory for writing and orders its metadata
	// itself, so the directory sync is skipped there, as syncDir does.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("durable: %w", err)
	}
	defer dir.Close()
	if err := sync(dir); err != nil {
		return fmt.Errorf("durable: syncing %s: %w", filepath.Dir(path), err)
	}
	return nil
}
