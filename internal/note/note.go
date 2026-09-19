// Package note implements the signed-note framing of SPEC.md §7 and the Norn
// submission receipt.
//
// A signed note is a block of text, a blank line, then one signature line per
// signer. The signed text runs through the newline that ends the last text line
// and excludes the blank separator -- a boundary worth stating plainly, because
// getting it wrong produces signatures that verify against nothing.
package note

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// AlgEd25519 is the note signature algorithm byte.
const AlgEd25519 = 0x01

// SigPrefix opens a signature line: an em dash and a space.
const SigPrefix = "— "

// ReceiptHeader is the first line of a submission receipt.
const ReceiptHeader = "norn/receipt/v1"

// ErrNote reports a malformed note, a malformed key, or no trusted signature.
var ErrNote = errors.New("note error")

func noteErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrNote, fmt.Sprintf(format, args...))
}

// KeyID binds a key to its name and algorithm: SHA-256(name || 0x0A || alg ||
// key)[:4]. One key under two names therefore has two ids.
func KeyID(name string, public []byte) []byte {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', AlgEd25519})
	h.Write(public)
	sum := h.Sum(nil)
	return sum[:4]
}

// VerifierKey renders `name+<keyid hex>+<base64(alg||key)>`.
func VerifierKey(name string, public []byte) string {
	data := base64.StdEncoding.EncodeToString(append([]byte{AlgEd25519}, public...))
	return fmt.Sprintf("%s+%s+%s", name, hex.EncodeToString(KeyID(name, public)), data)
}

// Verifier is a parsed verifier key.
type Verifier struct {
	Name   string
	Public []byte
}

// ID returns the verifier's 4-byte key id.
func (v Verifier) ID() []byte { return KeyID(v.Name, v.Public) }

// ParseVerifierKey reads a verifier key string and checks its embedded id.
func ParseVerifierKey(text string) (Verifier, error) {
	// At most twice: standard base64 key data may itself contain "+".
	parts := strings.SplitN(text, "+", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Verifier{}, noteErrorf("verifier key must be name+keyid+keydata")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return Verifier{}, noteErrorf("key data is not base64")
	}
	if len(raw) != ed25519.PublicKeySize+1 || raw[0] != AlgEd25519 {
		return Verifier{}, noteErrorf("only Ed25519 verifier keys are supported")
	}
	v := Verifier{Name: parts[0], Public: raw[1:]}
	if parts[1] != hex.EncodeToString(v.ID()) {
		return Verifier{}, noteErrorf("key id does not match the name and key")
	}
	return v, nil
}

// Sign returns the signed note: text, a blank line, one signature line.
func Sign(text, name string, key ed25519.PrivateKey) (string, error) {
	if text == "" || !strings.HasSuffix(text, "\n") {
		return "", noteErrorf("note text must be non-empty and end with a newline")
	}
	public := key.Public().(ed25519.PublicKey)
	blob := append(KeyID(name, public), ed25519.Sign(key, []byte(text))...)
	return fmt.Sprintf("%s\n%s%s %s\n", text, SigPrefix, name,
		base64.StdEncoding.EncodeToString(blob)), nil
}

// Signature is one parsed signature line.
type Signature struct {
	Name  string
	KeyID []byte
	Sig   []byte
}

// Split separates a signed note into its text and its signature lines.
func Split(signed string) (string, []Signature, error) {
	text, block, found := strings.Cut(signed, "\n\n")
	if !found {
		return "", nil, noteErrorf("note has no signature block")
	}
	text += "\n"

	var sigs []Signature
	for _, line := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
		if !strings.HasPrefix(line, SigPrefix) {
			return "", nil, noteErrorf("bad signature line %q", line)
		}
		name, blob, ok := strings.Cut(strings.TrimPrefix(line, SigPrefix), " ")
		if !ok {
			return "", nil, noteErrorf("signature line has no key name")
		}
		raw, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			return "", nil, noteErrorf("signature is not base64")
		}
		if len(raw) != 4+ed25519.SignatureSize {
			return "", nil, noteErrorf("signature must be a 4-byte key id plus 64 bytes")
		}
		sigs = append(sigs, Signature{Name: name, KeyID: raw[:4], Sig: raw[4:]})
	}
	if len(sigs) == 0 {
		return "", nil, noteErrorf("note has no signature lines")
	}
	return text, sigs, nil
}

// Verify returns the note text if any listed key signed it.
func Verify(signed string, vkeys []string) (string, error) {
	text, sigs, err := Split(signed)
	if err != nil {
		return "", err
	}
	trusted := make([]Verifier, 0, len(vkeys))
	for _, raw := range vkeys {
		v, err := ParseVerifierKey(raw)
		if err != nil {
			return "", err
		}
		trusted = append(trusted, v)
	}
	for _, sig := range sigs {
		for _, v := range trusted {
			if v.Name != sig.Name || string(v.ID()) != string(sig.KeyID) {
				continue
			}
			if ed25519.Verify(v.Public, []byte(text), sig.Sig) {
				return text, nil
			}
		}
	}
	return "", noteErrorf("no valid signature from a trusted key")
}

// ReceiptText builds the body of a submission receipt (§7).
func ReceiptText(origin string, leafHash []byte, deadline uint64) (string, error) {
	if len(leafHash) != sha256.Size {
		return "", noteErrorf("leaf hash must be %d bytes", sha256.Size)
	}
	return fmt.Sprintf("%s\n%s\n%s\n%d\n", ReceiptHeader, origin,
		base64.StdEncoding.EncodeToString(leafHash), deadline), nil
}
