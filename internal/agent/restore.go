package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/refusal"
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
	mirror := logclient.Dir(dir)
	result, err := logclient.Verify(mirror, a.anchorFor(nil))
	// The trust file names the keys and policy from before any in-log
	// rotation (D-020), and the point of rotating in the log is that nobody
	// re-provisions. So a mirror this node accepted under a key or a policy it
	// had learned is refused here for exactly those two reasons, and is
	// verified once more under what its own entries publish -- the same
	// authority the node used to accept it: a root quorum, replayed from the
	// pinned genesis. Any other refusal is not about what the node had learned
	// and gets no second attempt.
	if code, _ := refusal.CodeOf(err); code == refusal.LogSignature || code == refusal.Quorum {
		if published, perr := logclient.Published(mirror, a.replayAnchor()); perr == nil {
			result, err = logclient.Verify(mirror, a.anchorUnder(published))
		}
	}
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
