// Package entry defines the log entry envelope of SPEC.md §4: its typed model,
// its canonical encoding, the domain-separated signature preimage, and the two
// hashes derived from an entry's bytes.
//
// The model is typed rather than map-shaped so that the compiler enforces what
// the schema says, and so that "re-encode from the decoded model" is a real
// round trip rather than a copy of the input bytes.
package entry

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/onembyte/norn/internal/cbor"
)

// Version is the only envelope version this package speaks.
const Version = uint64(1)

// PreimagePrefix domain-separates entry signatures from every other use of
// these keys: 13 ASCII characters and one newline (SPEC §4.0).
const PreimagePrefix = "norn/entry/v1\n"

// NetLen, KeyLen and SigLen are the fixed byte lengths of §4.0.
const (
	NetLen = 16
	KeyLen = 32
	SigLen = 64
)

// Types is the closed set of entry types (SPEC §4.3).
var Types = map[string]bool{
	"genesis": true, "enroll": true, "rotate": true, "revoke": true,
	"signer_add": true, "signer_remove": true, "signer_thr": true,
	"root_add": true, "root_remove": true, "root_thr": true,
	"log_key": true, "policy": true, "params": true, "note": true,
}

// Roles is the closed set of signature roles (SPEC §4.1).
var Roles = map[string]bool{"root": true, "signer": true, "device": true}

// ErrSchema reports an envelope that does not match §4.1 or §4.3.
var ErrSchema = errors.New("entry schema violation")

func schemaErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSchema, fmt.Sprintf(format, args...))
}

// Signature is one entry in the `sigs` array.
type Signature struct {
	Kid  string
	Role string
	Sig  []byte
}

// Envelope is a decoded entry. After is nil when the optional field is absent,
// which is distinct from it being zero (SPEC §4.0: absent, never null).
type Envelope struct {
	V     uint64
	T     string
	Net   []byte
	TS    uint64
	After *uint64
	Body  map[string]any
	Sigs  []Signature
}

// Kid derives a key id: the first 8 bytes of SHA-256 over the public key,
// lowercase hex (SPEC §4.0).
func Kid(public []byte) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:8])
}

// EntryHash is the de-duplication identity of an entry's bytes.
func EntryHash(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

// LeafHash is the RFC 6962 §2.1 leaf hash of an entry's bytes.
func LeafHash(raw []byte) []byte {
	sum := sha256.Sum256(append([]byte{0x00}, raw...))
	return sum[:]
}

func (e *Envelope) toMap(withSigs bool) (map[string]any, error) {
	if !Types[e.T] {
		return nil, schemaErrorf("unknown entry type %q", e.T)
	}
	if len(e.Net) != NetLen {
		return nil, schemaErrorf("net must be %d bytes", NetLen)
	}
	if e.V != Version {
		return nil, schemaErrorf("unsupported version %d", e.V)
	}
	out := map[string]any{
		"v": e.V, "t": e.T, "net": e.Net, "ts": e.TS, "body": e.Body,
	}
	if e.After != nil {
		out["after"] = *e.After
	}
	if withSigs {
		sigs := make([]any, 0, len(e.Sigs))
		for _, s := range e.Sigs {
			if !Roles[s.Role] {
				return nil, schemaErrorf("unknown role %q", s.Role)
			}
			if len(s.Sig) != SigLen {
				return nil, schemaErrorf("signature must be %d bytes", SigLen)
			}
			sigs = append(sigs, map[string]any{"kid": s.Kid, "role": s.Role, "sig": s.Sig})
		}
		out["sigs"] = sigs
	}
	return out, nil
}

// Encode returns the canonical bytes of an entry, signatures included.
func Encode(e *Envelope) ([]byte, error) {
	m, err := e.toMap(true)
	if err != nil {
		return nil, err
	}
	return cbor.Encode(m)
}

// Preimage returns the bytes every signature on this entry covers: the domain
// prefix, then the envelope encoded WITHOUT its `sigs` key (SPEC §4.2).
func Preimage(e *Envelope) ([]byte, error) {
	m, err := e.toMap(false)
	if err != nil {
		return nil, err
	}
	encoded, err := cbor.Encode(m)
	if err != nil {
		return nil, err
	}
	return append([]byte(PreimagePrefix), encoded...), nil
}

// Sign adds one signature in place, keeping `sigs` sorted by kid and unique.
//
// The key is a crypto.Signer rather than an ed25519.PrivateKey so that a key
// held by an ssh-agent -- a hardware token, a password manager -- is the same
// thing to an entry as a key in memory (§16.3). ed25519
// .PrivateKey already satisfies the interface, so an in-memory key is passed
// exactly as before.
//
// What comes back from a signer is checked before it is kept: §3 allows only
// Ed25519, and a signature of the wrong length is a broken or hostile agent,
// not a signature. A failure at any point leaves the envelope untouched.
func Sign(e *Envelope, key crypto.Signer, role string) error {
	if !Roles[role] {
		return schemaErrorf("unknown role %q", role)
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return schemaErrorf("signing key is %T, and §3 allows only Ed25519", key.Public())
	}
	pre, err := Preimage(e)
	if err != nil {
		return err
	}
	// crypto.Hash(0) is what pure Ed25519 requires: the message is signed
	// whole, not pre-hashed.
	sig, err := key.Sign(rand.Reader, pre, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("the signer refused: %w", err)
	}
	if len(sig) != SigLen {
		return schemaErrorf("the signer returned %d bytes, want %d", len(sig), SigLen)
	}

	kid := Kid(public)
	kept := e.Sigs[:0:0]
	for _, s := range e.Sigs {
		if s.Kid != kid {
			kept = append(kept, s)
		}
	}
	kept = append(kept, Signature{Kid: kid, Role: role, Sig: sig})
	sort.Slice(kept, func(i, j int) bool { return kept[i].Kid < kept[j].Kid })
	e.Sigs = kept
	return nil
}

// Verify reports whether one signature checks out under a public key. The kid
// must also match the key, so a signature cannot be counted for a key it does
// not name.
func Verify(e *Envelope, sig Signature, public []byte) (bool, error) {
	if len(public) != KeyLen || len(sig.Sig) != SigLen {
		return false, nil
	}
	if Kid(public) != sig.Kid {
		return false, nil
	}
	pre, err := Preimage(e)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(public, pre, sig.Sig), nil
}
