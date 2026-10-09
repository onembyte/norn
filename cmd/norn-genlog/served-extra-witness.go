// These vectors write the served-extra-witness directory.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
)

// writeExtraWitnessHead ships §10's rule for a line the reader does not know.
//
// Cold gate run 9, D17: §10 says every line naming a witness the policy lists
// must verify, and nothing at all about a line naming a key the reader has
// never heard of. `07-unnamed-witness-only` is refused either way -- for want
// of a quorum -- so the suite could not separate "ignore it" from "refuse over
// it", and a reader that refuses stops accepting checkpoints everybody else
// accepts the moment a witness cosigns a log its policy does not list. That is
// normal in a shared log.
func writeExtraWitnessHead(root, signed string, signers []cosignpkg.Signer) error {
	stranger, err := seedKey(root, "stranger")
	if err != nil {
		return err
	}
	const name = "norn-witness/stranger"
	head, err := cosignpkg.Append([]cosignpkg.Signer{{Name: name, Key: stranger}},
		cosignpkg.At(time.Unix(CosignedAt+int64(4*CosignSpread), 0)))(signed)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-extra-witness")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
		return err
	}
	meta := map[string]any{
		"serve_over": "served",
		"stranger":   name,
		"comment": "the served head with one MORE cosignature line, from a witness " +
			"the policy never names and the trust file does not list. It verifies " +
			"under its own key and counts for nothing. SPEC 10: a line naming a " +
			"witness the policy lists must verify; a line naming anyone else is " +
			"IGNORED, not refused -- a witness cosigning a log this node's policy " +
			"does not list is normal in a shared log, and a reader that refuses " +
			"over it stops accepting checkpoints everybody else accepts. This head " +
			"MUST be accepted. Serve it in place of served/checkpoint over the " +
			"same tiles",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}
