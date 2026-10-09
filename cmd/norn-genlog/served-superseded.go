// These vectors write the served-superseded directory.

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
)

// writeSupersededHead ships §9.4's policy case: the served head cosigned by
// exactly two witnesses.
//
// The fixture's roots raise the quorum from two of three to three of three, so
// this head satisfies the trust file's policy and not the one the log
// publishes. Like `served-rotated/` it has two correct answers, and this time
// the informed reader is the stricter one: raising a quorum has to bind the
// nodes that were already watching, or it protects only the ones who were not.
func writeSupersededHead(root, origin, signed string, key ed25519.PrivateKey,
	signers []cosignpkg.Signer) error {

	if len(signers) < 3 {
		return fmt.Errorf("the fixture has %d witnesses; this case needs three", len(signers))
	}
	body, err := noteBody(signed)
	if err != nil {
		return err
	}
	head, err := note.Sign(body, origin, key)
	if err != nil {
		return err
	}
	head, err = staggeredCosigner(signers[:2])(head)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-superseded")
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
		"serve_over":  "served",
		"cosigned_by": []string{signers[0].Name, signers[1].Name},
		"comment": "the served head cosigned by two of the three witnesses. A reader " +
			"holding only trust.cbor requires two and MUST accept it; a reader that has " +
			"replayed this log has seen its roots raise the quorum to three and MUST " +
			"refuse it (SPEC 9.4). Serve it in place of served/checkpoint over the same " +
			"tiles. Two correct answers again, and here the informed reader is the " +
			"stricter one",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}
