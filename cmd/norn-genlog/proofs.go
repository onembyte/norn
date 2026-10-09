// These vectors write the proofs directory.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/tlog"
	upstream "golang.org/x/mod/sumdb/tlog"
)

// writeRightEdgeProof records the RFC 6962 shape D13b found missing: the last
// leaf of a 127-entry tree, where a parity-only inclusion reader answers
// differently. The entry, root and proof are all shipped so a second reader
// can check the path without rebuilding this generator's tree.
func writeRightEdgeProof(dir string, entries [][]byte) error {
	const size, index = 127, 126
	if len(entries) < size {
		return fmt.Errorf("right-edge proof needs %d entries, fixture has %d", size, len(entries))
	}
	tree, err := tlog.Build(entries[:size])
	if err != nil {
		return err
	}
	proof, err := tree.InclusionProof(index)
	if err != nil {
		return err
	}
	leaf := tlog.LeafHash(entries[index])
	head := tree.Head()
	if err := upstream.CheckRecord(proof, size, head, index, leaf); err != nil {
		return fmt.Errorf("generated right-edge proof does not verify: %w", err)
	}
	proofHex := make([]string, len(proof))
	for i, hash := range proof {
		proofHex[i] = hex.EncodeToString(hash[:])
	}
	doc := map[string]any{
		"comment":   "right-edge inclusion proof for the last leaf of a 127-entry tree (D13b)",
		"size":      size,
		"index":     index,
		"entry_b64": base64.StdEncoding.EncodeToString(entries[index]),
		"leaf_hash": hex.EncodeToString(leaf[:]),
		"root":      hex.EncodeToString(head[:]),
		"proof":     proofHex,
	}
	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "right-edge.json"), append(blob, '\n'), 0o644)
}
