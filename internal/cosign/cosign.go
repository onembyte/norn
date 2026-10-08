// Package cosign checks the witness cosignatures on a checkpoint
// (`c2sp.org/tlog-cosignature` v1).
//
// `GOSSIP.md` part 1: witnesses guard against the log. A log that shows two
// nodes two different histories can sign both, but it cannot get a witness to
// cosign both at the same size — so a cosignature is the difference between
// "the operator says this is the log" and "somebody else saw this too".
//
// A cosignature also carries the only clock Norn trusts. A node's wall clock
// is untrusted (A11) and a checkpoint has no timestamp of its own, so witness
// time is what makes "how old is this view" answerable at all.
package cosign

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
)

// Header is the first line of the signed message.
const Header = "cosignature/v1"

// ErrCosign reports a malformed or unverifiable cosignature.
var ErrCosign = errors.New("cosignature error")

func cosignErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCosign, fmt.Sprintf(format, args...))
}

// Cosignature is one witness's statement about a checkpoint.
type Cosignature struct {
	// Name is the witness's note name, as the trust file lists it.
	Name string
	// Public is the witness key that signed.
	Public ed25519.PublicKey
	// Time is what the witness said the time was. This is the clock.
	Time time.Time
}

// Message is the bytes a cosignature covers: a header line, a timestamp line,
// and the checkpoint's note body including its final newline.
func Message(at time.Time, body string) []byte {
	return fmt.Appendf(nil, "%s\ntime %d\n%s", Header, at.Unix(), body)
}

// Verify returns every cosignature on the note that a trusted witness key
// accounts for.
//
// Unknown signature lines are ignored rather than refused: a checkpoint may
// carry cosignatures from witnesses this node has never heard of, and that is
// somebody else's business. What matters is which of *this* network's
// witnesses have vouched for it.
//
// A refusal carries §10.1's code: `cosignature` for a listed witness's line
// that does not verify, `note` for a note that does not frame. A witness key
// that does not parse, or is a plain note key, is the policy's mistake rather
// than the checkpoint's, so it is reported first and carries no code.
func Verify(signed string, witnessKeys []string) ([]Cosignature, error) {
	trusted := make([]note.Verifier, 0, len(witnessKeys))
	for _, raw := range witnessKeys {
		v, err := note.ParseVerifierKey(raw)
		if err != nil {
			return nil, cosignErrorf("witness key: %v", err)
		}
		if !v.IsCosigner() {
			return nil, cosignErrorf("%s is a note key, not a cosignature key: a witness "+
				"publishes algorithm 0x%02x", v.Name, note.AlgCosignature)
		}
		trusted = append(trusted, v)
	}

	body, sigs, err := note.Split(signed)
	if err != nil {
		return nil, refusal.Wrap(refusal.Note, cosignErrorf("%v", err))
	}

	var out []Cosignature
	for _, sig := range sigs {
		for _, v := range trusted {
			if v.Name != sig.Name || string(v.ID()) != string(sig.KeyID) {
				continue
			}
			// §7: once name and key id match a trusted key, the payload is
			// exactly that key's length. A line under a listed witness's name
			// and id with a note signature's length is a claim the witness
			// cannot have made, and is refused like a forgery -- not skipped,
			// which let a head carried by other lines through (SEC-027; the
			// log side is checkpoints-bad/24).
			if !sig.IsCosignature() {
				return nil, refusal.Wrap(refusal.Cosignature,
					cosignErrorf("%s's line is %d bytes, not a cosignature", v.Name, len(sig.KeyID)+len(sig.Sig)))
			}
			at := time.Unix(int64(binary.BigEndian.Uint64(sig.Sig[:8])), 0)
			if !ed25519.Verify(v.Public, Message(at, body), sig.Sig[8:]) {
				return nil, refusal.Wrap(refusal.Cosignature,
					cosignErrorf("%s signed a cosignature that does not verify", v.Name))
			}
			out = append(out, Cosignature{Name: v.Name, Public: v.Public, Time: at})
			break
		}
	}
	return out, nil
}

// Sign produces a cosignature line, which is what a witness returns and what
// the log appends to the checkpoint it serves.
func Sign(body string, name string, key ed25519.PrivateKey, at time.Time) (string, error) {
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return "", cosignErrorf("a witness key must be Ed25519")
	}
	signature := ed25519.Sign(key, Message(at, body))
	payload := note.KeyIDFor(name, public, note.AlgCosignature)
	payload = binary.BigEndian.AppendUint64(payload, uint64(at.Unix()))
	payload = append(payload, signature...)
	return note.SignatureLine(name, payload), nil
}

// Signer is one witness's signing identity: the name its cosignature carries
// and the key that produces it.
type Signer struct {
	Name string
	Key  ed25519.PrivateKey
}

// Append returns the step a log takes once its witnesses have answered: one
// cosignature line per witness, appended to the head the log signed (§6). The
// body and the log's own signature are left exactly as they were.
//
// A log whose witnesses run elsewhere gets those lines over
// `c2sp.org/tlog-witness` instead; this is for the case where the keys are
// held locally -- the fixture generator, and a lab where the witness is a
// process on the same host.
//
// The clock is a parameter because a live log stamps each checkpoint with the
// time it was cosigned -- that stamp is the only clock a verifier trusts (A11)
// -- while a fixture needs the same instant every run to stay reproducible.
func Append(signers []Signer, now func() time.Time) func(signed string) (string, error) {
	return func(signed string) (string, error) {
		at := now()
		body, _, err := note.Split(signed)
		if err != nil {
			return "", err
		}
		out := signed
		for _, s := range signers {
			line, err := Sign(body, s.Name, s.Key, at)
			if err != nil {
				return "", cosignErrorf("%s could not cosign: %v", s.Name, err)
			}
			out += line + "\n"
		}
		return out, nil
	}
}

// At is the clock a fixture uses: the same instant every time, so a regenerated
// fixture is byte-identical to the shipped one.
func At(instant time.Time) func() time.Time {
	return func() time.Time { return instant }
}
