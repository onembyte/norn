package tlog

import (
	upstream "golang.org/x/mod/sumdb/tlog"
)

// Tree is an in-memory log: every leaf hash, and the interior hashes derived
// from them. It exists so that proofs can be produced and checked in tests and
// by the CLI before the on-disk log of 2.3 exists; the log server keeps the
// same shape but reads its hashes from storage.
type Tree struct {
	hashes []upstream.Hash // indexed by StoredHashIndex
	size   int64
}

// Build appends every entry in order and returns the resulting tree.
func Build(entries [][]byte) (*Tree, error) {
	t := &Tree{}
	for _, raw := range entries {
		if err := t.Append(raw); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// Append adds one entry, storing the hashes its addition creates.
func (t *Tree) Append(raw []byte) error {
	next, err := upstream.StoredHashesForRecordHash(t.size, LeafHash(raw), t)
	if err != nil {
		return err
	}
	t.hashes = append(t.hashes, next...)
	t.size++
	return nil
}

// Size is the number of entries.
func (t *Tree) Size() int64 { return t.size }

// Head is the tree head at the current size.
func (t *Tree) Head() upstream.Hash {
	head, err := upstream.TreeHash(t.size, t)
	if err != nil {
		// TreeHash can only fail if a stored hash is missing, which would mean
		// this tree was built inconsistently -- a bug here, not bad input.
		panic("tlog: inconsistent tree: " + err.Error())
	}
	return head
}

// ReadHashes implements upstream.HashReader.
func (t *Tree) ReadHashes(indexes []int64) ([]upstream.Hash, error) {
	out := make([]upstream.Hash, len(indexes))
	for i, index := range indexes {
		if index < 0 || index >= int64(len(t.hashes)) {
			return nil, formatErrorf("hash index %d out of range", index)
		}
		out[i] = t.hashes[index]
	}
	return out, nil
}

// InclusionProof proves that the entry at index is in the tree at its current
// size.
func (t *Tree) InclusionProof(index int64) (upstream.RecordProof, error) {
	return upstream.ProveRecord(t.size, index, t)
}

// ConsistencyProof proves that the tree at `older` is a prefix of this one.
func (t *Tree) ConsistencyProof(older int64) (upstream.TreeProof, error) {
	return upstream.ProveTree(t.size, older, t)
}

// Checkpoint returns the tree head as a checkpoint body for an origin.
func (t *Tree) Checkpoint(origin string) Checkpoint {
	return Checkpoint{Origin: origin, Size: t.size, Root: t.Head()}
}

// Tile is one hash tile the layout requires a log to serve.
type Tile struct {
	Level int
	Index int64
	Width int
	Data  []byte // Width hashes, concatenated
}

// Path is where this tile is served (tlog-tiles).
func (t Tile) Path() string { return TilePath(t.Level, t.Index, t.Width) }

// Tiles enumerates every hash tile this tree implies, with its contents.
//
// The writer publishes these and the verifier checks them against its own
// tree, so the computation lives here rather than in either: a reader and a
// writer that each work out "what should be in tile 3" separately are two
// implementations of one rule, and the second one is the one that is wrong.
func (t *Tree) Tiles() ([]Tile, error) {
	var out []Tile
	size := t.Size()
	for level := 0; ; level++ {
		span := int64(1) << (uint(level+1) * TileHeight)
		count := (size + span/TileWidth - 1) / (span / TileWidth)
		if count == 0 {
			return out, nil
		}
		for index := int64(0); index < count; index++ {
			data, width, err := t.tileData(level, index)
			if err != nil {
				return nil, err
			}
			if width == 0 {
				continue
			}
			out = append(out, Tile{Level: level, Index: index, Width: width, Data: data})
		}
		if count == 1 && size <= span/TileWidth {
			return out, nil
		}
	}
}

// tileData reads one tile's hashes, stopping at the end of the level.
func (t *Tree) tileData(level int, index int64) ([]byte, int, error) {
	var out []byte
	var width int
	for i := 0; i < TileWidth; i++ {
		n := index*TileWidth + int64(i)
		stored := upstream.StoredHashIndex(level*TileHeight, n)
		hashes, err := t.ReadHashes([]int64{stored})
		if err != nil {
			break // past the end of this level
		}
		out = append(out, hashes[0][:]...)
		width++
	}
	return out, width, nil
}
