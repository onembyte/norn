package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
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
	dir := filepath.Join(a.cfg.RunDir, proven.MirrorDir)
	// A first start has no mirror, and neither does a node that crashed
	// before its first copy finished: the checkpoint is written last
	// (mirror.Write), so without one there is no head to restore and nothing
	// worth saying.
	if _, err := os.Stat(filepath.Join(dir, "checkpoint")); errors.Is(err, fs.ErrNotExist) {
		return
	}
	result, err := logclient.Verify(logclient.Dir(dir), a.anchorFor(nil))
	if err != nil {
		// A disk fault, a half-overwritten copy, or another network's log in
		// a reused run directory. Not a reason to refuse to start -- a node
		// with no mirror starts too -- and never a head to hold, but worth an
		// alarm: this restart has lost the protection D-069 gives.
		a.emit(Event{Kind: MirrorUnusable, Message: fmt.Sprintf(
			"the mirror in %s does not verify under this trust file (%v); starting "+
				"without the head this node held, so nothing protects this first "+
				"cycle from an older head of the log", dir, err)})
		return
	}
	a.restored = result
}
