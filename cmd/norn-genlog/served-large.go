// These vectors write the served-large directory.

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/tlogstore"
)

// writeServedLarge exercises the real paths a log reaches after one tile.
// The ordinary replay fixture is intentionally compact; append unique signed
// note entries to a copy so the generated head crosses both tile boundaries
// without changing the protocol state exercised by the other vectors.
func writeServedLarge(root, origin string, net []byte, entries [][]byte,
	logKey ed25519.PrivateKey, signers []cosignpkg.Signer) error {
	const size = 300
	if len(entries) > size {
		return fmt.Errorf("the replay fixture has %d entries, more than the scale log", len(entries))
	}
	scaleEntries := append([][]byte(nil), entries...)
	signerKey, err := seedKey(root, "signer1")
	if err != nil {
		return err
	}
	for index := len(scaleEntries); index < size; index++ {
		after := uint64(index)
		env := &entry.Envelope{
			V: entry.Version, T: "note", Net: append([]byte(nil), net...),
			TS: uint64(CosignedAt + int64(index)), After: &after,
			Body: map[string]any{"text": fmt.Sprintf("multi-tile scale entry %03d", index)},
		}
		if err := entry.Sign(env, signerKey, "signer"); err != nil {
			return fmt.Errorf("sign scale entry %d: %w", index, err)
		}
		raw, err := entry.Encode(env)
		if err != nil {
			return fmt.Errorf("encode scale entry %d: %w", index, err)
		}
		scaleEntries = append(scaleEntries, raw)
	}

	dir := filepath.Join(root, "served-large")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	store, err := tlogstore.Open(dir, origin, logKey, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(staggeredCosigner(signers))))
	if err != nil {
		return err
	}
	for index, raw := range scaleEntries {
		if _, err := store.Append(raw); err != nil {
			return fmt.Errorf("append scale entry %d: %w", index, err)
		}
	}

	tree, err := tlog.Build(scaleEntries)
	if err != nil {
		return err
	}
	tiles, err := tree.Tiles()
	if err != nil {
		return err
	}
	type tileCase struct {
		Path  string `json:"path"`
		Width int    `json:"width"`
	}
	listed := make([]tileCase, 0, len(tiles))
	for _, tile := range tiles {
		listed = append(listed, tileCase{Path: tile.Path(), Width: tile.Width})
	}
	type pathCase struct {
		Kind  string `json:"kind"`
		Level int    `json:"level"`
		Index int64  `json:"index"`
		Width int    `json:"width"`
		Path  string `json:"path"`
	}
	// The served tree cannot reach a four-digit tile index without growing
	// to 256,000 entries. A path table pins the group boundaries separately.
	var paths []pathCase
	for _, index := range []int64{0, 1, 255, 256, 999, 1000, 1001, 255999, 256000, 1234567} {
		paths = append(paths,
			pathCase{"hash", 0, index, tlog.TileWidth, tlog.TilePath(0, index, tlog.TileWidth)},
			pathCase{"hash", 0, index, 44, tlog.TilePath(0, index, 44)},
			pathCase{"hash", 1, index, 1, tlog.TilePath(1, index, 1)},
			pathCase{"entries", 0, index, tlog.TileWidth, tlog.EntryBundlePath(index, tlog.TileWidth)})
	}
	meta := map[string]any{
		"size":  size,
		"tiles": listed,
		"paths": paths,
		"comment": "a 300-entry, signed and cosigned served log. It exercises a full " +
			"level-0 tile, a partial level-0 tile, and the level-1 tile; every listed " +
			"tile path and width is implied by the checkpoint. The separate paths " +
			"table checks hash and entry-bundle path functions at group boundaries, " +
			"including indices beyond this log; entries rows use no hash level",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}
