// These vectors write the served-stranger-name directory.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
)

// writeStrangerNameHead ships where D-074 (f)'s grammar stops.
//
// A key name is one or more ASCII bytes 0x21-0x7E without '+' -- a rule about
// verifier keys, the names a trust file and a policy may give. A signature
// line's name is only matched against those keys, never parsed by the rule,
// so a stranger who cosigns under a name no verifier key here could carry is
// ignored like any other stranger (D-074 c). A reader that applied the
// grammar to every line it read would refuse heads every other reader of a
// shared log accepts.
func writeStrangerNameHead(root, signed string) error {
	stranger, err := seedKey(root, "stranger")
	if err != nil {
		return err
	}
	const name = "witness.example/zürich"
	head, err := cosignpkg.Append([]cosignpkg.Signer{{Name: name, Key: stranger}},
		cosignpkg.At(time.Unix(CosignedAt+int64(6*CosignSpread), 0)))(signed)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-stranger-name")
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
		"comment": "the served head with one MORE cosignature line, from a stranger " +
			"whose name is not ASCII -- a name SPEC 7's key-name grammar would " +
			"refuse in a verifier key. The grammar is a verifier key's; a " +
			"signature line's name is only matched against verifier keys, so " +
			"this line names nobody and is ignored (D-074 c, f). This head MUST " +
			"be accepted. Serve it in place of served/checkpoint over the same tiles",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}
