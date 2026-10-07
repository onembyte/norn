//go:build !linux

package durable

// Volatile reports whether dir is on a filesystem that does not survive a
// reboot. Only Linux is checked: it is where `nornd`'s defaults put `/run`
// on a tmpfs. Elsewhere the answer is false, which an operator who mounts a
// RAM disk under the state directory should not rely on.
func Volatile(dir string) (bool, error) { return false, nil }
