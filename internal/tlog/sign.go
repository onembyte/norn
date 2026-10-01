package tlog

import (
	"crypto/ed25519"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
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
//
// It is §10.1's steps 2 to 4, and a refusal carries the code of the step that
// made it: the note's framing (`note`), then the log's signature
// (`log-signature`), then the body (`checkpoint`). The order is the order of
// dependence -- there are no signatures to check until the lines are found,
// and no body worth parsing until something trusted signed it. The origin, the
// cosignatures and the quorum are the caller's, because they need the anchor.
//
// A trusted key that does not parse is the caller's configuration, not the
// checkpoint's fault: it is reported first and carries no code.
func Verify(signed string, vkeys []string) (Checkpoint, error) {
	for _, raw := range vkeys {
		if _, err := note.ParseVerifierKey(raw); err != nil {
			return Checkpoint{}, err
		}
	}
	if _, _, err := note.Split(signed); err != nil {
		return Checkpoint{}, refusal.Wrap(refusal.Note, err)
	}
	text, err := note.Verify(signed, vkeys)
	if err != nil {
		return Checkpoint{}, refusal.Wrap(refusal.LogSignature, err)
	}
	cp, err := ParseCheckpoint(text)
	if err != nil {
		return Checkpoint{}, refusal.Wrap(refusal.Checkpoint, err)
	}
	return cp, nil
}
