package main

import (
	"fmt"
	"os"

	"github.com/onembyte/norn/internal/durable"
)

// stateDirWarnings says why state_dir would not keep what it is for: the
// mirror whose head this node holds across a restart (D-069) and the
// evidence whose presence is a fork freeze (§11). Each is a warning and
// nothing more -- a node that cannot keep its freeze still enforces, and
// refusing to start would leave the network with no node at all.
//
// The directory is created here if it is missing, as the first mirror would
// create it anyway; finding out now is the point.
func stateDirWarnings(dir string) []string {
	const lost = "the head this node holds and any fork freeze"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return []string{fmt.Sprintf("state_dir %s cannot be created (%v): %s "+
			"will not survive a restart", dir, err, lost)}
	}
	probe, err := os.CreateTemp(dir, ".nornd-probe-*")
	if err != nil {
		return []string{fmt.Sprintf("state_dir %s cannot be written (%v): %s "+
			"will not survive a restart", dir, err, lost)}
	}
	probe.Close()
	os.Remove(probe.Name())

	if volatile, err := durable.Volatile(dir); err == nil && volatile {
		return []string{fmt.Sprintf("state_dir %s is on a tmpfs: %s will survive "+
			"a restart but will not survive a reboot; point state_dir at disk, "+
			"such as %s", dir, lost, DefaultStateDir)}
	}
	return nil
}
