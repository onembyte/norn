// These vectors write the served-name-collision directory.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
)

// writeNameCollisionHead ships §10's definition of "a line naming a witness".
//
// Cold gate run 9 settled the easy half -- a line from a name the policy does
// not list is ignored -- and run 10 (D16) found the hard one open: a line
// carrying a *listed* witness's name under somebody else's key. §7 makes the
// key id bind the name, the algorithm and the public key, so such a line names
// nobody and is ignored like any stranger's. The other reading, matching on
// the name alone, hands every party a veto: cosign a head under a name you do
// not hold and every node reading it that way refuses the head, including
// nodes that have never heard of you. `served-extra-witness/` cannot separate
// them, because its stranger uses a different name.
func writeNameCollisionHead(root, signed string, signers []cosignpkg.Signer) error {
	if len(signers) == 0 {
		return fmt.Errorf("no witnesses to collide with")
	}
	// The same key `served-extra-witness/` uses, under a different name. That
	// pairing is §7's point made twice: one key, two names, two key ids, and
	// both lines ignored -- one because the name is unknown, this one because
	// the id is.
	impostor, err := seedKey(root, "stranger")
	if err != nil {
		return err
	}
	// The first witness's NAME, the stranger's KEY. The line verifies under
	// that key and under no key the policy publishes.
	borrowed := signers[0].Name
	head, err := cosignpkg.Append([]cosignpkg.Signer{{Name: borrowed, Key: impostor}},
		cosignpkg.At(time.Unix(CosignedAt+int64(5*CosignSpread), 0)))(signed)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-name-collision")
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
		"witness":    borrowed,
		"comment": "the served head with one MORE cosignature line, carrying a " +
			"LISTED witness's name under a key the policy does not publish for " +
			"it. SPEC 10: a line names a witness the policy lists when its name " +
			"AND key id both match that witness's verifier key -- so this line " +
			"names nobody and is ignored, exactly like a stranger's. Two lines " +
			"carry the name and one carries the key id. This head MUST be " +
			"accepted; a reader matching on the name alone refuses it, which " +
			"would let anyone deny a head to every node on the network by " +
			"cosigning it under a name they do not hold. Serve it in place of " +
			"served/checkpoint over the same tiles",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}
