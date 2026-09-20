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
func Verify(signed string, witnessKeys []string) ([]Cosignature, error) {
	body, sigs, err := note.Split(signed)
	if err != nil {
		return nil, cosignErrorf("%v", err)
	}

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

	var out []Cosignature
	for _, sig := range sigs {
		if !sig.IsCosignature() {
			continue
		}
		for _, v := range trusted {
			if v.Name != sig.Name || string(v.ID()) != string(sig.KeyID) {
				continue
			}
			at := time.Unix(int64(binary.BigEndian.Uint64(sig.Sig[:8])), 0)
			if !ed25519.Verify(v.Public, Message(at, body), sig.Sig[8:]) {
				return nil, cosignErrorf("%s signed a cosignature that does not verify", v.Name)
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
