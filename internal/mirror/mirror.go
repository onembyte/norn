// Package mirror writes a verified log to disk so a node can serve it to its
// peers.
//
// `GOSSIP.md` part 6: "it holds all of them — full replication". A node that
// remembered only the checkpoint could tell a peer what it believes but could
// not prove it, and gossip works precisely because a peer serves **data, never
// claims**: the receiver recomputes the consistency proof from tiles it
// fetched, so a lying peer is caught by the same code that catches a lying
// log. That property costs nothing extra here, because the layout a node
// writes is the layout it read.
//
// It is also what buys liveness under a log freeze (T2): one node that got the
// new checkpoint is enough for the whole connected mesh, but only if it kept
// the bytes.
package mirror

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/tlog"
)

// ErrMirror reports a mirror that could not be written.
var ErrMirror = errors.New("mirror error")

func mirrorErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMirror, fmt.Sprintf(format, args...))
}

// Write copies a verified log into `dir` in `tlog-tiles` layout: the entry
// bundles, every hash tile the tree implies, and the signed checkpoint exactly
// as the log published it — cosignatures and all, since a head stripped of
// them is one no correctly-configured node will accept.
//
// It is a no-op when the mirror already holds this head, because a node polls
// on `T_poll` and a mirror that rewrote every file each cycle would turn a
// 24-hour soak into a disk benchmark. That is the same property `PLAN.md`
// requires of the peer table: unchanged input, no writes.
// The checkpoint arrives already parsed, which is the caller saying it
// verified this head rather than merely fetched it: `logclient.Result` carries
// both halves, and a mirror built from an unverified note would replicate
// whatever a bad log served.
func Write(dir string, cp tlog.Checkpoint, signedCheckpoint string, entries [][]byte) error {
	tree, err := tlog.Build(entries)
	if err != nil {
		return mirrorErrorf("rebuilding the tree: %v", err)
	}
	// A checkpoint that does not describe these entries would produce a mirror
	// whose own tiles contradict its head -- which every peer reading it would
	// report as a broken log, naming this node.
	if cp.Size != tree.Size() {
		return mirrorErrorf("the checkpoint claims %d entries, %d were given",
			cp.Size, tree.Size())
	}
	if cp.Root != tree.Head() {
		return mirrorErrorf("the entries do not hash to the head the checkpoint claims")
	}

	if current, err := os.ReadFile(filepath.Join(dir, "checkpoint")); err == nil {
		if bytes.Equal(current, []byte(signedCheckpoint)) {
			return nil
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for index := int64(0); index*tlog.TileWidth < tree.Size(); index++ {
		first := index * tlog.TileWidth
		last := min(first+tlog.TileWidth, tree.Size())
		bundle := entries[first:last]
		if err := write(dir, tlog.EntryBundlePath(index, len(bundle)),
			tlog.EncodeBundle(bundle)); err != nil {
			return err
		}
	}
	tiles, err := tree.Tiles()
	if err != nil {
		return mirrorErrorf("computing tiles: %v", err)
	}
	for _, tile := range tiles {
		if err := write(dir, tile.Path(), tile.Data); err != nil {
			return err
		}
	}
	// The checkpoint goes last, so a crash leaves a mirror advertising less
	// than it holds rather than more -- the same ordering the log itself uses.
	return write(dir, "checkpoint", []byte(signedCheckpoint))
}

func write(dir, rel string, data []byte) error {
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(temp, path)
}
