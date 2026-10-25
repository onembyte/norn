package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/mirror"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
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
	// The first directory holding a mirror is the one to restore: the state
	// directory, or the run directory a version before the split wrote to. A
	// first start has no mirror, and neither does a node that crashed before
	// its first copy finished -- the checkpoint is written last
	// (mirror.Write) -- so without one there is no head to restore and
	// nothing worth saying.
	var dir string
	for _, candidate := range a.stateDirs() {
		mirrorDir := filepath.Join(candidate, proven.MirrorDir)
		if _, err := os.Stat(filepath.Join(mirrorDir, "checkpoint")); !errors.Is(err, fs.ErrNotExist) {
			dir = mirrorDir
			break
		}
	}
	if dir == "" {
		return
	}
	result, err := a.restoreMirror(dir)
	if err != nil {
		// A disk fault, a half-overwritten copy, or another network's log in
		// a reused directory cannot supply the rollback protection D-069 gives.
		a.emit(Event{Kind: MirrorUnusable, Message: fmt.Sprintf(
			"the mirror in %s does not verify under its acceptance and this trust file (%v); starting "+
				"without the head this node held, so nothing protects this first "+
				"cycle from an older head of the log", dir, err)})
		return
	}
	a.restored = result
}

// restoreMirror reads acceptance before choosing a policy. Parsing the head
// only locates its record; Verify still checks the signature, quorum, entries
// and tiles under that policy and the root-authorized log keys (§9.4).
func (a *Agent) restoreMirror(dir string) (*logclient.Result, error) {
	source := logclient.Dir(dir)
	raw, err := source.Fetch("checkpoint")
	if err != nil {
		return nil, err
	}
	body, _, err := note.Split(string(raw))
	if err != nil {
		return nil, err
	}
	cp, err := tlog.ParseCheckpoint(body)
	if err != nil {
		return nil, err
	}
	acceptance, err := mirror.ReadAcceptance(dir, cp)
	if err != nil {
		return nil, err
	}
	if acceptance != nil {
		published, err := logclient.Published(source, a.replayAnchor())
		if err != nil {
			return nil, err
		}
		anchor := a.anchorUnder(published)
		anchor.Policy = acceptance.Policy
		result, err := verify(source, anchor)
		if err != nil {
			return nil, err
		}
		// The stored note still proves the accepted time. Refuse a torn or
		// edited record rather than letting local metadata invent witness time.
		if (result.QuorumTime == nil) != (acceptance.QuorumTime == nil) ||
			(result.QuorumTime != nil && !result.QuorumTime.Equal(*acceptance.QuorumTime)) {
			return nil, fmt.Errorf("the mirror's persisted acceptance time does not match its signed note")
		}
		result.QuorumTime = acceptance.QuorumTime
		return result, nil
	}
	// A mirror from an older version has no persisted acceptance. Keep its
	// trust-file-first path, then retry under published authority only for a
	// log-signature or quorum refusal, as before D-082 (1).
	result, err := verify(source, a.anchorFor(nil))
	// The trust file names the keys and policy from before any in-log
	// rotation (D-020), and the point of rotating in the log is that nobody
	// re-provisions. So a mirror this node accepted under a key or a policy it
	// had learned is refused here for exactly those two reasons, and is
	// verified once more under what its own entries publish -- the same
	// authority the node used to accept it: a root quorum, replayed from the
	// pinned genesis. Any other refusal is not about what the node had learned
	// and gets no second attempt.
	if code, _ := refusal.CodeOf(err); code == refusal.LogSignature || code == refusal.Quorum {
		if published, perr := logclient.Published(source, a.replayAnchor()); perr == nil {
			result, err = verify(source, a.anchorUnder(published))
		}
	}
	return result, err
}
