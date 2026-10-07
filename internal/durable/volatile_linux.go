//go:build linux

package durable

import (
	"fmt"
	"syscall"
)

// The filesystems whose contents a reboot discards, by the magic number
// statfs(2) reports for them (linux/magic.h).
const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

// Volatile reports whether dir is on a filesystem that does not survive a
// reboot: a tmpfs or a ramfs. `/run` is one on every systemd host, which is
// why `nornd` keeps its state elsewhere (SEC-006).
func Volatile(dir string) (bool, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false, fmt.Errorf("durable: %w", err)
	}
	// The field's type differs by architecture; the magic numbers are 32 bits
	// on all of them.
	switch uint32(st.Type) {
	case tmpfsMagic, ramfsMagic:
		return true, nil
	}
	return false, nil
}
