package logclient

import (
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlog"
)

// Published is the state a served log's entries replay to, read **without**
// verifying its head: no signature, no quorum, no tree.
//
// It exists for one question, which Verify cannot answer by itself: which log
// keys and which witness policy does this log publish (§9.4), so that its head
// can then be verified under them? A node restoring its own mirror after an
// in-log rotation needs exactly that (D-069), because its trust file still
// names the keys from before the rotation.
//
// Nothing it returns may be enforced, held, or trusted. A forged head can
// claim any size, and only Verify decides whether a log is believed. What
// makes the answer usable at all is replay: every entry is checked against
// the roots of the pinned genesis, so the keys and policy it reports are the
// ones a root quorum published -- which is the authority §9.4 gives them.
func Published(f Fetcher, anchor replay.Anchor) (*state.State, error) {
	raw, err := f.Fetch("checkpoint")
	if err != nil {
		return nil, refuse(refusal.Unserved, "fetching the checkpoint: %v", err)
	}
	text, _, err := note.Split(string(raw))
	if err != nil {
		return nil, logErrorf("the checkpoint does not frame: %v", err)
	}
	cp, err := tlog.ParseCheckpoint(text)
	if err != nil {
		return nil, logErrorf("the checkpoint does not parse: %v", err)
	}
	entries, err := fetchEntries(f, cp.Size)
	if err != nil {
		return nil, err
	}
	return replay.Replay(anchor, entries), nil
}
