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
	"unicode/utf8"

	"github.com/onembyte/norn/internal/ed25519v1"
)

// AlgEd25519 is the note signature algorithm byte.
const AlgEd25519 = 0x01

// AlgCosignature is the algorithm byte of a witness's key
// (`c2sp.org/tlog-cosignature` v1).
//
// It is not a formality. The byte goes into the key id, so the same public key
// published as a note signer and as a cosigner is **two different verifiers**.
// Norn encoded witness keys with 0x01 until 4.1a, which meant its own
// validator would have rejected a trust file naming a real witness -- and a
// cosignature from one could never have been attributed to it.
const AlgCosignature = 0x04

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
	return KeyIDFor(name, public, AlgEd25519)
}

// KeyIDFor is KeyID for a given algorithm.
func KeyIDFor(name string, public []byte, alg byte) []byte {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', alg})
	h.Write(public)
	sum := h.Sum(nil)
	return sum[:4]
}

// VerifierKey renders `name+<keyid hex>+<base64(alg||key)>`.
func VerifierKey(name string, public []byte) string {
	return VerifierKeyFor(name, public, AlgEd25519)
}

// CosignerVerifierKey renders a witness's key: the same shape, algorithm 0x04.
func CosignerVerifierKey(name string, public []byte) string {
	return VerifierKeyFor(name, public, AlgCosignature)
}

// VerifierKeyFor renders a verifier key for a given algorithm.
func VerifierKeyFor(name string, public []byte, alg byte) string {
	data := base64.StdEncoding.EncodeToString(append([]byte{alg}, public...))
	return fmt.Sprintf("%s+%s+%s", name, hex.EncodeToString(KeyIDFor(name, public, alg)), data)
}

// Verifier is a parsed verifier key.
type Verifier struct {
	Name   string
	Public []byte
	// Alg distinguishes a note signer (0x01) from a witness cosigner (0x04).
	Alg byte
}

// ID returns the verifier's 4-byte key id.
func (v Verifier) ID() []byte {
	alg := v.Alg
	if alg == 0 {
		alg = AlgEd25519
	}
	return KeyIDFor(v.Name, v.Public, alg)
}

// IsCosigner reports whether this key signs cosignatures rather than notes.
func (v Verifier) IsCosigner() bool { return v.Alg == AlgCosignature }

// ParseVerifierKey reads a verifier key string and checks its embedded id.
func ParseVerifierKey(text string) (Verifier, error) {
	// At most twice: standard base64 key data may itself contain "+".
	parts := strings.SplitN(text, "+", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Verifier{}, noteErrorf("verifier key must be name+keyid+keydata")
	}
	if !validKeyName(parts[0]) {
		return Verifier{}, noteErrorf("verifier key name %q is not one or more ASCII bytes 0x21-0x7E without '+'", parts[0])
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(parts[2])
	if err != nil || base64.StdEncoding.EncodeToString(raw) != parts[2] {
		return Verifier{}, noteErrorf("key data is not base64")
	}
	if len(raw) != ed25519.PublicKeySize+1 ||
		(raw[0] != AlgEd25519 && raw[0] != AlgCosignature) {
		return Verifier{}, noteErrorf("only Ed25519 note and cosignature keys are supported")
	}
	v := Verifier{Name: parts[0], Public: raw[1:], Alg: raw[0]}
	// The algorithm is part of the identity, so it is part of the id check.
	if parts[1] != hex.EncodeToString(v.ID()) {
		return Verifier{}, noteErrorf("key id does not match the name, key and algorithm")
	}
	return v, nil
}

// validKeyName is §7's key-name grammar (D-074 f): one or more ASCII bytes
// from 0x21 to 0x7E, '+' excluded. It was unicode.IsSpace, and the Unicode
// tables behind that and Python's str.isspace disagree on U+001C-U+001F, so
// a trust file loaded in one implementation and not the other. A grammar has
// no table to disagree about; every name Norn issues is already inside it.
func validKeyName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x21 || c > 0x7e || c == '+' {
			return false
		}
	}
	return true
}

// validSignatureName is the looser signed-note grammar, not a verifier key's
// ASCII grammar. The white-space property is written out so a runtime's
// Unicode table cannot change which stranger lines frame (D-077).
func validSignatureName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		switch c {
		case '+', '\u0009', '\u000a', '\u000b', '\u000c', '\u000d',
			'\u0020', '\u0085', '\u00a0', '\u1680', '\u2000', '\u2001',
			'\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2007',
			'\u2008', '\u2009', '\u200a', '\u2028', '\u2029', '\u202f',
			'\u205f', '\u3000':
			return false
		}
	}
	return true
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
	// Sig is everything after the key id: 64 bytes for a note signature, or
	// a timestamp and 64 bytes for a cosignature. What it means depends on
	// the algorithm of the key the id resolves to.
	Sig []byte
}

// IsCosignature reports whether this line carries a timestamped signature.
func (s Signature) IsCosignature() bool { return len(s.Sig) == 8+ed25519.SignatureSize }

// Split separates a signed note into its text and its signature lines.
func Split(signed string) (string, []Signature, error) {
	// The text and every signature line are UTF-8 (§7, D-074 c): a reader
	// that decodes before it verifies must see the same bytes this one does.
	if !utf8.ValidString(signed) {
		return "", nil, noteErrorf("the note is not UTF-8")
	}
	// The whole note follows signed-note's control-byte rule, including
	// unknown signature lines that would otherwise be ignored (D-077).
	for i := 0; i < len(signed); i++ {
		if signed[i] < 0x20 && signed[i] != '\n' {
			return "", nil, noteErrorf("the note contains an ASCII control character")
		}
	}
	text, block, found := strings.Cut(signed, "\n\n")
	if !found {
		return "", nil, noteErrorf("note has no signature block")
	}
	text += "\n"

	// Every signature line ends in a newline, the last one included. This
	// accepted a block that simply stopped, so a note with an unterminated
	// final line was valid here and invalid to a stricter reader
	// (cold gate run 8, D21).
	if !strings.HasSuffix(block, "\n") {
		return "", nil, noteErrorf("the signature block does not end in a newline")
	}
	// Remove exactly the one required terminator. Trimming all trailing LFs
	// made a note with a blank line after its final signature indistinguishable
	// from one whose last signature line ended correctly (D14b).
	block = strings.TrimSuffix(block, "\n")
	var sigs []Signature
	for _, line := range strings.Split(block, "\n") {
		if !strings.HasPrefix(line, SigPrefix) {
			return "", nil, noteErrorf("bad signature line %q", line)
		}
		name, blob, ok := strings.Cut(strings.TrimPrefix(line, SigPrefix), " ")
		if !ok || !validSignatureName(name) {
			return "", nil, noteErrorf("signature line has an invalid key name")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(blob)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != blob {
			return "", nil, noteErrorf("signature is not base64")
		}
		// Framing asks only for the key id. The rest is the matched key's to
		// judge -- 64 bytes for a note key, 8 + 64 for a cosigner -- and a
		// line no trusted key matches is ignored whatever its length, as
		// `c2sp.org/signed-note` says. Refusing every length but 68 and 76
		// here refused checkpoints carrying a cosignature on an algorithm
		// nobody here knows (D-074 c, corrected 2026-10-10).
		if len(raw) < 4 {
			return "", nil, noteErrorf("signature must start with a 4-byte key id")
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
	// Per line, not per key. This returned on the first line that verified, so
	// a note carrying a valid signature **and** a forgery under the same key
	// was accepted and the forgery never looked at -- the same reading §10
	// settles for cosignatures, on the log itself (cold gate run 8, D21).
	var verified bool
	for _, sig := range sigs {
		for _, v := range trusted {
			if v.Name != sig.Name || v.IsCosigner() || string(v.ID()) != string(sig.KeyID) {
				continue
			}
			// A 76-byte payload is a valid frame in isolation, but it is the
			// other algorithm's length for this matched note key. Resolve the
			// name and key ID before deciding that a line is an unrelated
			// cosignature; §10.1 assigns this failure to log-signature (D14c).
			if len(sig.Sig) != ed25519.SignatureSize {
				return "", noteErrorf("a signature line naming %s has the wrong length", v.Name)
			}
			if !ed25519v1.Verify(v.Public, []byte(text), sig.Sig) {
				return "", noteErrorf("a signature line naming %s does not verify", v.Name)
			}
			verified = true
		}
	}
	if !verified {
		return "", noteErrorf("no valid signature from a trusted key")
	}
	return text, nil
}

// ReceiptText builds the body of a submission receipt (§7).
func ReceiptText(origin string, leafHash []byte, deadline uint64) (string, error) {
	if len(leafHash) != sha256.Size {
		return "", noteErrorf("leaf hash must be %d bytes", sha256.Size)
	}
	return fmt.Sprintf("%s\n%s\n%s\n%d\n", ReceiptHeader, origin,
		base64.StdEncoding.EncodeToString(leafHash), deadline), nil
}

// SignatureLine renders one signature line: the em-dash prefix, the key name,
// and base64 of the key id followed by the signature payload.
func SignatureLine(name string, payload []byte) string {
	return SigPrefix + name + " " + base64.StdEncoding.EncodeToString(payload)
}
