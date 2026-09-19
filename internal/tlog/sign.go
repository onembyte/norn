package tlog

import (
	"crypto/ed25519"

	"github.com/onembyte/norn/internal/note"
)

// Sign renders the checkpoint as a signed note (tlog-checkpoint).
//
// The note's key name is the origin, which §9.1 also requires of the trust
// file's log key: it binds the signature to this network, so a checkpoint
// signed by a key named for another origin cannot verify here even if the key
// itself is trusted somewhere.
func (c Checkpoint) Sign(key ed25519.PrivateKey) (string, error) {
	return note.Sign(c.Marshal(), c.Origin, key)
}

// Verify checks a signed checkpoint under the given verifier keys and returns
// the checkpoint it carries.
func Verify(signed string, vkeys []string) (Checkpoint, error) {
	text, err := note.Verify(signed, vkeys)
	if err != nil {
		return Checkpoint{}, err
	}
	return ParseCheckpoint(text)
}
