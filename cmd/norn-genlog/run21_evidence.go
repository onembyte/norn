package main

import (
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
)

// The evidence is unsigned. Preserve both genuine notes and the main proof;
// each split negative changes only the claim about their common prefix.
func writeRunTwentyOneEvidence(root string) error {
	for _, name := range []string{"bad-bool-version", "bad-split-held-root-at-own-size", "bad-split-conflicting-root-at-own-size"} {
		parent := "evidence-at-same-size.cbor"
		code, phrase := "proof", "each as step 3 does, with the same rule at a head's own size: no proof,"
		if name == "bad-bool-version" {
			parent = "evidence-v1.cbor"
			code, phrase = "version", "absent, not a uint, or another number"
		}
		raw, err := os.ReadFile(filepath.Join(root, "fork", parent))
		if err != nil {
			return err
		}
		m := mustMap(raw)
		if name == "bad-bool-version" {
			m["version"] = true
		} else {
			other := "conflicting"
			if name == "bad-split-conflicting-root-at-own-size" {
				other = "held"
			}
			text, _, err := note.Split(m[other].(string))
			if err != nil {
				return err
			}
			cp, err := tlog.ParseCheckpoint(text)
			if err != nil {
				return err
			}
			m["split"] = m["size"]
			m["split_root"] = append([]byte(nil), cp.Root[:]...)
			m["split_proof_held"], m["split_proof_conflicting"] = []any{}, []any{}
		}
		raw, err = cbor.Encode(m)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, "fork", name+".cbor"), raw, 0o644); err != nil {
			return err
		}
		says := map[string]string{"bad-bool-version": "version true is not a uint version", "bad-split-held-root-at-own-size": "split_root differs from held's signed root at held's own size, with no split proofs", "bad-split-conflicting-root-at-own-size": "split_root differs from conflicting's signed root at conflicting's own size, with no split proofs"}[name]
		if err := extendRunFourteenManifest(root, "fork", []map[string]string{{"name": name, "says": says}}, map[string]string{name: code}, map[string]map[string]string{name: {"section": "11.1", "says": phrase}}, false); err != nil {
			return err
		}
	}
	return nil
}
