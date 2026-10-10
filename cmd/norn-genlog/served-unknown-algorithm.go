// These vectors write the served-unknown-algorithm directory.

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/note"
)

// unknownAlgorithm is an algorithm byte §7 does not use. The key id binds it,
// so the line below names a key nobody here could hold even if they held the
// stranger's public key.
const unknownAlgorithm = 0xff

// writeUnknownAlgorithmHead ships D-074 (c)'s rule for a stranger's length.
//
// §7 frames every line -- canonical base64 of at least a 4-byte key id -- and
// leaves the rest to the key the line matches. A line no trusted key matches is
// ignored whatever its length: a witness on a shared log may cosign under an
// algorithm this document does not use, and refusing the head over it stops a
// Norn reader accepting what every other reader accepts. Every stranger's line
// elsewhere in the suite is 76 bytes, so a reader that framed only 68 and 76
// passed all of them; this one is 70.
func writeUnknownAlgorithmHead(root, signed string) error {
	stranger, err := seedKey(root, "stranger")
	if err != nil {
		return err
	}
	text, _, err := note.Split(signed)
	if err != nil {
		return err
	}
	const name = "norn-witness/elsewhere"
	h := sha256.New()
	h.Write([]byte(name + "\n"))
	h.Write([]byte{unknownAlgorithm})
	h.Write(stranger.Public().(ed25519.PublicKey))
	id := h.Sum(nil)[:4]
	// Sixty-six bytes nobody can check: a digest of the text, so the line is
	// the same every time the suite is generated.
	sum := sha512.Sum512([]byte(text))
	payload := append(append(append([]byte{}, id...), sum[:]...), sum[:2]...)
	head := signed + note.SignatureLine(name, payload) + "\n"

	dir := filepath.Join(root, "served-unknown-algorithm")
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
		"serve_over":    "served",
		"stranger":      name,
		"payload_bytes": len(payload),
		"comment": "the served head with one MORE signature line, from a key nobody " +
			"here holds under an algorithm SPEC 7 does not use: a 4-byte key id and " +
			"66 bytes, 70 in all, neither 68 nor 76. SPEC 7: framing asks every line " +
			"only for canonical base64 of at least a key id; the length is the " +
			"matched key's to judge, and a line no trusted key matches is ignored " +
			"whatever its length (D-074 c). This head MUST be accepted. Serve it in " +
			"place of served/checkpoint over the same tiles",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}
