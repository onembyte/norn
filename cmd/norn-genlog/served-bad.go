// These vectors write the served-bad directory.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
)

// leafHashTile turns an entry bundle into the level-0 tile it implies: each
// entry's `H(0x00 ‖ entry)`, concatenated. A served log whose tile is this is
// internally consistent whatever the entries say.
func leafHashTile(bundle []byte) []byte {
	var out []byte
	for len(bundle) >= 2 {
		n := int(bundle[0])<<8 | int(bundle[1])
		if len(bundle) < 2+n {
			return nil
		}
		sum := sha256.Sum256(append([]byte{0x00}, bundle[2:2+n]...))
		out = append(out, sum[:]...)
		bundle = bundle[2+n:]
	}
	return out
}

// writeBadServed ships §6's refusals of a served log. A served log is a
// directory rather than a file, so the case says which path to replace or
// remove.
func writeBadServed(root, served string, size int64) error {
	dir := filepath.Join(root, "served-bad")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	if size <= 0 {
		return fmt.Errorf("cannot build served-bad vectors for an empty log")
	}
	lastBundleIndex := (size - 1) / tlog.TileWidth
	lastBundleWidth := int((size-1)%tlog.TileWidth) + 1
	bundlePath := tlog.EntryBundlePath(lastBundleIndex, lastBundleWidth)
	honest, err := os.ReadFile(filepath.Join(served, filepath.FromSlash(bundlePath)))
	if err != nil {
		return err
	}
	lastEntries, err := tlog.DecodeBundle(honest)
	if err != nil {
		return fmt.Errorf("decode last bundle %s: %w", bundlePath, err)
	}
	if len(lastEntries) != lastBundleWidth {
		return fmt.Errorf("last bundle %s holds %d entries, want %d",
			bundlePath, len(lastEntries), lastBundleWidth)
	}
	tooMany := append(append([][]byte(nil), lastEntries...), lastEntries[len(lastEntries)-1])
	overfull, err := tlog.EncodeBundle(tooMany)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "overfull-entry-bundle.bin"),
		overfull, 0o644); err != nil {
		return err
	}
	// One byte inside an entry, so the bundle still frames correctly and only
	// the leaf hash it produces is wrong.
	tampered := append([]byte(nil), honest...)
	tampered[len(tampered)-1] ^= 0x01
	if err := os.WriteFile(filepath.Join(dir, "tampered-entry-bundle.bin"),
		tampered, 0o644); err != nil {
		return err
	}

	// Cold-model gate run 7, defect J4. Both cases above are *entry bundle*
	// cases, so until this one nothing in the suite ever opened a hash tile
	// and `blind-tiles` -- a verifier that never fetches `tile/0/...` at all
	// -- reproduced the whole manifest. One byte inside one leaf hash leaves
	// the entries and the signed head untouched, so the tile rule of SPEC 6
	// is the only thing that can refuse it.
	tilePath := tlog.TilePath(0, lastBundleIndex, lastBundleWidth)
	honestTile, err := os.ReadFile(filepath.Join(served, filepath.FromSlash(tilePath)))
	if err != nil {
		return err
	}
	badTile := append([]byte(nil), honestTile...)
	badTile[len(badTile)-1] ^= 0x01
	if err := os.WriteFile(filepath.Join(dir, "tampered-hash-tile.bin"),
		badTile, 0o644); err != nil {
		return err
	}

	// Cold-model gate run 10, defect D11. Both tamper cases above CAN be
	// refused by the tile rule alone: changing a byte of an entry changes its
	// leaf hash, so the served tile disagrees and a reader never has to
	// compare the rebuilt head with the checkpoint at all. `V154_NoRebuild`
	// passed all 236 checks on exactly that. (§10.1 checks the head first, so
	// `tampered-entry-bundle` is `head` -- and a tiles-first or tiles-only
	// reader answers `tiles`, which is what makes it the head-before-tiles
	// vector now that cases carry codes.) Here the tile is recomputed over the tampered
	// entries, so the served directory agrees with itself -- and the tree it
	// describes is not the one the checkpoint is signed over. Only "compares
	// its head with the signed checkpoint" can see it.
	consistentTile := leafHashTile(tampered)
	if len(consistentTile) != len(honestTile) {
		return fmt.Errorf("recomputed tile is %d bytes, the served one is %d",
			len(consistentTile), len(honestTile))
	}
	if bytes.Equal(consistentTile, honestTile) {
		return fmt.Errorf("the recomputed tile equals the honest one, so the " +
			"tampered entry did not change its leaf hash")
	}
	if err := os.WriteFile(filepath.Join(dir, "consistent-entry-bundle.bin"),
		tampered, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "consistent-hash-tile.bin"),
		consistentTile, 0o644); err != nil {
		return err
	}

	// D-061: the §10.1 code each is refused with. The head is checked before
	// the tiles, so the tampered bundle -- whose tiles disagree as well -- is
	// `head`.
	servedCodes := map[string]refusal.Code{
		"tampered-entry-bundle":   refusal.Head,
		"missing-entry-bundle":    refusal.Unserved,
		"consistent-tampered-log": refusal.Head,
		"tampered-hash-tile":      refusal.Tiles,
		"overfull-entry-bundle":   refusal.Entries,
		"missing-hash-tile":       refusal.Unserved,
		"missing-checkpoint":      refusal.Unserved,
	}
	servedCases := []map[string]any{
		{"name": "tampered-entry-bundle", "path": bundlePath,
			"file": "tampered-entry-bundle.bin",
			"says": "one byte of one entry changed: the bundle still frames, and the " +
				"tree it builds is not the one the checkpoint is signed over"},
		{"name": "missing-entry-bundle", "path": bundlePath, "remove": true,
			"says": "a log that will not serve its entries cannot be replayed, and a " +
				"verifier must refuse rather than report what it has"},
		{"name": "consistent-tampered-log", "files": []map[string]string{
			{"path": bundlePath, "file": "consistent-entry-bundle.bin"},
			{"path": tilePath, "file": "consistent-hash-tile.bin"},
		},
			"says": "the entries and the hash tile are tampered *together*, so the " +
				"served log agrees with itself and disagrees with the head the " +
				"checkpoint is signed over: only rebuilding the tree and comparing " +
				"that head can refuse it"},
		{"name": "tampered-hash-tile", "path": tilePath,
			"file": "tampered-hash-tile.bin",
			"says": "one byte of one leaf hash changed: the entries and the signed " +
				"head are untouched, so a verifier that reaches the head without " +
				"opening `tile/0/...` sees nothing wrong, and serves the corrupt " +
				"tile onward to peers asking it for proofs"},
		{"name": "overfull-entry-bundle", "path": bundlePath,
			"file": "overfull-entry-bundle.bin",
			"says": "the bundle decodes but holds one more entry than the checkpoint " +
				"size and its path imply"},
		// Cold gate run 13, D18: step 1's code for the two files no case had
		// taken away. A reader that skips a tile it cannot fetch, or reports
		// a missing checkpoint as a malformed one, passed.
		{"name": "missing-hash-tile", "path": tilePath, "remove": true,
			"says": "step 11 needs the hash tile to check the served tree, and it is " +
				"not served: refused, not skipped"},
		{"name": "missing-checkpoint", "path": "checkpoint", "remove": true,
			"says": "no checkpoint is served, so there is nothing to verify: " +
				"`unserved`, not a framing error over an empty note"},
	}
	if err := checkCodes("served-bad", namesOf(servedCases), servedCodes, refusal.Known); err != nil {
		return err
	}

	meta := map[string]any{
		"rules": map[string]map[string]string{
			// 6.5l-vi-b-ii-e: both cited §6's tile sentence. The tampered
			// bundle is refused by the head comparison before any tile is
			// opened, and a missing bundle by §10.1's `unserved`.
			"tampered-entry-bundle":   {"section": "6", "says": "that comparison is what binds the entries to the head"},
			"missing-entry-bundle":    {"section": "10.1", "says": "any file a later step needs and cannot fetch"},
			"tampered-hash-tile":      {"section": "6", "says": "checking them is not optional"},
			"consistent-tampered-log": {"section": "6", "says": "that comparison is what binds the entries to the head"},
			"overfull-entry-bundle":   {"section": "6", "says": "A partial bundle holds **exactly** the number of entries its path declares"},
			"missing-hash-tile":       {"section": "10.1", "says": "any file a later step needs and cannot fetch"},
			"missing-checkpoint":      {"section": "10.1", "says": "any file a later step needs and cannot fetch"},
		},
		"cases":      servedCases,
		"codes":      servedCodes,
		"serve_over": "served-large",
		"comment": "a served log is a directory, so each case names the path to replace " +
			"with `file`, the paths to replace with `files`, or the path to delete " +
			"with `remove`, over an otherwise honest copy of `served-large/`. Every one " +
			"MUST be refused, with the SPEC §10.1 code `codes` names for it",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}
