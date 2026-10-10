// These vectors write the served-genesis directory.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/refusal"
)

// writeServedGenesis ships §10.1's `genesis` (D-074 (g)) for a reader that
// holds no head: a log signed and cosigned exactly as this network's is, whose
// entry 0 is not the genesis the trust file pins, and a log with no entries at
// all. Both are detect/'s directories; there, served to a reader that holds
// the earlier head, the first is a `fork` and the second a `rollback`. One
// pair of logs and two answers, decided by what the reader already holds --
// that is the amendment of 2026-10-10, and why `genesis` comes after the
// comparison: it must never hide the equivocation a held head can prove.
func writeServedGenesis(root string) error {
	dir := filepath.Join(root, "served-genesis")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	meta := map[string]any{
		"cases": []map[string]string{
			{"name": "another-genesis", "serve": "../detect/other-genesis",
				"says": "entry 0 is not the anchored genesis"},
			{"name": "empty", "serve": "../detect/empty",
				"says": "the log has no entry 0"},
		},
		"codes": map[string]refusal.Code{
			"another-genesis": refusal.Genesis,
			"empty":           refusal.Genesis,
		},
		"rules": map[string]map[string]string{
			"another-genesis": {"section": "10.1",
				"says": "its entry 0 is not the genesis the anchor pins"},
			"empty": {"section": "10.1", "says": "the served log has no entry 0"},
		},
		"comment": "each case serves a directory under ../detect, tiles and all, to a " +
			"reader that holds no checkpoint and only trust.cbor. Both MUST be refused " +
			"with the SPEC 10.1 code `codes` names. detect/ serves the same two to a " +
			"reader holding detect/earlier.checkpoint, which MUST answer `fork` and " +
			"`rollback`: `genesis` is decided after the comparison with a held head",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}
