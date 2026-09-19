// Package logclient reads a served Norn log and verifies it: the verifier loop
// of SPEC.md §10.
//
// A log is fetched through a Fetcher, so the same code reads a directory on
// disk, a static web server, or a peer over the tunnel. The interface is one
// method wide on purpose -- everything a verifier needs from a log is "give me
// the bytes at this path", and keeping it that narrow is what makes gossip
// (§6) a different Fetcher rather than a different verifier.
package logclient

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlog"
)

// ErrLog reports a log that cannot be trusted: unreachable, inconsistent, or
// serving entries that do not match the head it advertises.
var ErrLog = errors.New("log error")

func logErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrLog, fmt.Sprintf(format, args...))
}

// Fetcher returns the bytes at a log-relative path, or an error.
type Fetcher interface {
	Fetch(path string) ([]byte, error)
}

// Dir serves a log from a directory on disk.
type Dir string

// Fetch implements Fetcher.
func (d Dir) Fetch(path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(string(d), filepath.FromSlash(path)))
}

// Result is what a successful verification yields.
type Result struct {
	Checkpoint tlog.Checkpoint
	State      *state.State
	Entries    int
}

// Verify fetches a log, checks that the entries it serves really do hash to
// the head it advertises, and replays them under the anchor.
//
// The order matters: integrity BEFORE replay. Replaying first and checking
// afterwards would mean acting on entries that were never shown to belong to
// the log -- exactly the trust a transparency log exists to remove.
func Verify(f Fetcher, anchor replay.Anchor) (*Result, error) {
	raw, err := f.Fetch("checkpoint")
	if err != nil {
		return nil, logErrorf("fetching the checkpoint: %v", err)
	}
	cp, err := tlog.ParseCheckpoint(string(raw))
	if err != nil {
		return nil, err
	}

	entries, err := fetchEntries(f, cp.Size)
	if err != nil {
		return nil, err
	}

	// Rebuild the tree from what was served and require the advertised head.
	tree, err := tlog.Build(entries)
	if err != nil {
		return nil, logErrorf("building the tree: %v", err)
	}
	if tree.Size() != cp.Size {
		return nil, logErrorf("checkpoint claims %d entries, %d were served",
			cp.Size, tree.Size())
	}
	if tree.Head() != cp.Root {
		return nil, logErrorf("the served entries do not hash to the advertised head")
	}

	return &Result{Checkpoint: cp, State: replay.Replay(anchor, entries), Entries: len(entries)}, nil
}

// fetchEntries reads entry bundles until it has `size` entries.
func fetchEntries(f Fetcher, size int64) ([][]byte, error) {
	var out [][]byte
	for index := int64(0); int64(len(out)) < size; index++ {
		remaining := size - int64(len(out))
		width := tlog.TileWidth
		if remaining < int64(width) {
			width = int(remaining)
		}
		raw, err := fetchBundle(f, index, width)
		if err != nil {
			return nil, err
		}
		entries, err := decodeBundle(raw)
		if err != nil {
			return nil, err
		}
		if len(entries) == 0 {
			return nil, logErrorf("entry bundle %d is empty", index)
		}
		out = append(out, entries...)
	}
	if int64(len(out)) != size {
		return nil, logErrorf("served %d entries, the checkpoint claims %d", len(out), size)
	}
	return out, nil
}

// fetchBundle tries the full path first, then the partial one: a bundle is
// full unless it is the last, and the last carries its width in its path.
func fetchBundle(f Fetcher, index int64, width int) ([]byte, error) {
	if raw, err := f.Fetch(tlog.EntryBundlePath(index, tlog.TileWidth)); err == nil {
		return raw, nil
	}
	raw, err := f.Fetch(tlog.EntryBundlePath(index, width))
	if err != nil {
		return nil, logErrorf("fetching entry bundle %d: %v", index, err)
	}
	return raw, nil
}

func decodeBundle(raw []byte) ([][]byte, error) {
	var out [][]byte
	for len(raw) > 0 {
		if len(raw) < 2 {
			return nil, logErrorf("truncated entry bundle")
		}
		n := int(binary.BigEndian.Uint16(raw[:2]))
		if len(raw) < 2+n {
			return nil, logErrorf("entry bundle claims %d bytes but has %d", n, len(raw)-2)
		}
		out = append(out, raw[2:2+n])
		raw = raw[2+n:]
	}
	return out, nil
}
