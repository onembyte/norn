// Package tlog adapts a Norn log to the C2SP tiled-log formats: the tile and
// entry-bundle paths of tlog-tiles, and the signed tree head of
// tlog-checkpoint.
//
// The Merkle mathematics is golang.org/x/mod/sumdb/tlog's, not ours. Reusing it
// is PLAN.md ground rule 3, and a hand-rolled Merkle tree is precisely the kind
// of code that looks correct and is subtly wrong in a way no unit test written
// by its author would catch. What this package adds is the C2SP path layout,
// which x/mod does not implement -- it uses the sumdb scheme instead.
package tlog

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	upstream "golang.org/x/mod/sumdb/tlog"
)

// TileHeight and TileWidth are fixed by tlog-tiles: a full tile is 2^8 = 256
// hashes wide.
const (
	TileHeight = 8
	TileWidth  = 1 << TileHeight
)

// ErrFormat reports a malformed checkpoint or tile reference.
var ErrFormat = errors.New("tlog format error")

func formatErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, args...))
}

// LeafHash is the RFC 6962 §2.1 leaf hash of an entry's bytes.
func LeafHash(data []byte) upstream.Hash { return upstream.RecordHash(data) }

// pathIndex renders N as 3-digit groups separated by "/", every group but the
// last prefixed with "x": 1234067 becomes "x001/x234/067". Getting this wrong
// produces paths that look plausible and resolve to nothing.
func pathIndex(n int64) string {
	groups := []string{fmt.Sprintf("%03d", n%1000)}
	for n /= 1000; n > 0; n /= 1000 {
		groups = append([]string{fmt.Sprintf("x%03d", n%1000)}, groups...)
	}
	return strings.Join(groups, "/")
}

func withWidth(base string, width int) string {
	if width >= TileWidth {
		return base
	}
	return fmt.Sprintf("%s.p/%d", base, width)
}

// TilePath returns the path of one tile: `tile/<L>/<N>[.p/<W>]`.
func TilePath(level int, index int64, width int) string {
	return withWidth(fmt.Sprintf("tile/%d/%s", level, pathIndex(index)), width)
}

// EntryBundlePath returns the path of one entry bundle:
// `tile/entries/<N>[.p/<W>]`.
func EntryBundlePath(index int64, width int) string {
	return withWidth("tile/entries/"+pathIndex(index), width)
}

// Checkpoint is a signed tree head's note body (tlog-checkpoint): an origin
// line, a size line, and a base64 root. Extension lines are not used, and are
// refused on the way in.
type Checkpoint struct {
	Origin string
	Size   int64
	Root   upstream.Hash
}

// Marshal renders the checkpoint body, terminated by a newline.
func (c Checkpoint) Marshal() string {
	return fmt.Sprintf("%s\n%d\n%s\n", c.Origin, c.Size,
		base64.StdEncoding.EncodeToString(c.Root[:]))
}

// ParseCheckpoint reads a checkpoint body, rejecting anything that is not
// exactly the three specified lines in their canonical form.
func ParseCheckpoint(text string) (Checkpoint, error) {
	if !strings.HasSuffix(text, "\n") {
		return Checkpoint{}, formatErrorf("checkpoint must end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 3 {
		return Checkpoint{}, formatErrorf("checkpoint has %d lines, want 3", len(lines))
	}
	if lines[0] == "" {
		return Checkpoint{}, formatErrorf("origin must be non-empty")
	}
	// No leading zeroes, no sign: the size line has exactly one spelling.
	if lines[1] != strconv.FormatInt(parseSize(lines[1]), 10) {
		return Checkpoint{}, formatErrorf("size %q is not canonical", lines[1])
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 0 {
		return Checkpoint{}, formatErrorf("size %q is not a non-negative integer", lines[1])
	}
	raw, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return Checkpoint{}, formatErrorf("root is not base64")
	}
	var root upstream.Hash
	if len(raw) != len(root) {
		return Checkpoint{}, formatErrorf("root must be %d bytes, got %d", len(root), len(raw))
	}
	copy(root[:], raw)
	return Checkpoint{Origin: lines[0], Size: size, Root: root}, nil
}

// parseSize returns the integer value of s, or -1 if it is not one, so that the
// canonical-spelling check above can compare round trips without panicking.
func parseSize(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1
	}
	return n
}
