package agent

import (
	"path/filepath"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/proven"
)

// restoreHead reads back the head this node held before it last stopped
// (D-069, review finding F1).
//
// §10's comparison only protects a node that remembers what it held. Before
// this, a restarted node held nothing until its first verification, and
// `logclient.Verify` skips the comparison when there is nothing to compare
// against -- so the first head it was shown after a restart was accepted at any
// size, including an older head of this very log, correctly signed and
// cosigned because it *is* this log, earlier. Every revocation since was
// undone, and a restart is something an attacker can cause.
//
// The mirror is the node's own copy of the last log it verified, written as
// it verified it (GOSSIP part 6), and it is verified again here exactly as a
// log is: nothing on disk is believed because this node wrote it. What
// verifies becomes the held head only, never the enforced one -- see
// Agent.restored.
func (a *Agent) restoreHead() {
	if a.cfg.RunDir == "" {
		return
	}
	dir := logclient.Dir(filepath.Join(a.cfg.RunDir, proven.MirrorDir))
	result, err := logclient.Verify(dir, a.anchorFor(nil))
	if err != nil {
		return
	}
	a.restored = result
}
