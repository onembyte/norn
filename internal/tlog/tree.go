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
