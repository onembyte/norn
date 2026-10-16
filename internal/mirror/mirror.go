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
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/onembyte/norn/internal/durable"
	"github.com/onembyte/norn/internal/note"
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

	keep := make(map[string]bool)
	keepPartials(keep, cp.Size)
	cleanup := true
	if current, err := os.ReadFile(filepath.Join(dir, "checkpoint")); err == nil {
		if bytes.Equal(current, []byte(signedCheckpoint)) {
			return nil
		}
		text, _, err := note.Split(string(current))
		if err == nil {
			previous, err := tlog.ParseCheckpoint(text)
			if err == nil {
				keepPartials(keep, previous.Size)
			} else {
				cleanup = false
			}
		} else {
			cleanup = false
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// A malformed head's paths cannot be identified safely. Repairing its
	// checkpoint still works, but leave the old files until a later adoption.

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for index := int64(0); index*tlog.TileWidth < tree.Size(); index++ {
		first := index * tlog.TileWidth
		last := min(first+tlog.TileWidth, tree.Size())
		bundle := entries[first:last]
		framed, err := tlog.EncodeBundle(bundle)
		if err != nil {
			return err
		}
		if err := write(dir, tlog.EntryBundlePath(index, len(bundle)), framed); err != nil {
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
	if err := write(dir, "checkpoint", []byte(signedCheckpoint)); err != nil {
		return err
	}
	if !cleanup {
		return nil
	}
	return prunePartials(dir, keep)
}

// My understanding of c2sp.org/tlog-tiles is that wider partial or full tiles
// supersede narrower partials, which may be removed. This is from memory, not
// a quote of its exact wording. Keeping one previous generation delays that
// removal so a peer that just read our old checkpoint can fetch its exact
// paths with one request each; since D-079 logclient falls back to the full
// tile or bundle when the partial path is gone, so this is a courtesy, not a
// need.
func keepPartials(keep map[string]bool, size int64) {
	if width := int(size % tlog.TileWidth); width != 0 {
		keep[tlog.EntryBundlePath(size/tlog.TileWidth, width)] = true
	}
	for level := 0; size > 0; level++ {
		if width := int(size % tlog.TileWidth); width != 0 {
			keep[tlog.TilePath(level, size/tlog.TileWidth, width)] = true
		}
		size /= tlog.TileWidth
	}
}

// partialPath accepts only the canonical spelling produced by tlog, including
// grouped indices and widths 1 through 255. The mirror directory can contain
// operator files, so a similar-looking name is not enough to authorize removal.
func partialPath(path string) bool {
	parts := strings.Split(path, "/")
	if len(parts) < 4 || parts[0] != "tile" {
		return false
	}
	width, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil || width < 1 || width >= tlog.TileWidth {
		return false
	}
	last, ok := strings.CutSuffix(parts[len(parts)-2], ".p")
	if !ok {
		return false
	}
	groups := append([]string(nil), parts[2:len(parts)-2]...)
	for i := range groups {
		groups[i] = strings.TrimPrefix(groups[i], "x")
	}
	index, err := strconv.ParseInt(strings.Join(groups, "")+last, 10, 64)
	if err != nil || index < 0 {
		return false
	}
	if parts[1] == "entries" {
		return path == tlog.EntryBundlePath(index, width)
	}
	level, err := strconv.Atoi(parts[1])
	return err == nil && level >= 0 && path == tlog.TilePath(level, index, width)
}

// Cleanup follows checkpoint durability, so an interrupted adoption leaves
// extra files rather than a checkpoint naming missing ones. WalkDir does not
// follow symlinks, and Root keeps even a raced directory replacement from
// redirecting a removal outside the configured mirror.
func prunePartials(dir string, keep map[string]bool) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if path != "." && path != "tile" && !strings.HasPrefix(path, "tile/") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || d.Type()&os.ModeSymlink != 0 || !partialPath(path) || keep[path] {
			return nil
		}
		if err := removeFile(root, path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
}

// writeFile is the one writer every file of the mirror goes through --
// durable, so a head on disk never names a file the disk did not receive
// (H4-d; before this the mirror synced nothing, and after a power cut its
// restored head could point at a torn bundle, which D-069's restart then
// reported unusable). Replaceable so a test can watch the order.
var writeFile = durable.WriteFile

// removeFile is replaceable so a test can make a listed partial disappear
// immediately before removal, without depending on filesystem timing.
var removeFile = (*os.Root).Remove

// write puts a file in place if its bytes are not already there. A new head
// changes one partial bundle, the partial tiles and the checkpoint; the full
// bundles and tiles below it are the same bytes at the same paths, and
// rewriting them every head would turn a growing log into a disk benchmark
// of its own history.
func write(dir, rel string, data []byte) error {
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeFile(path, data, 0o644)
}
