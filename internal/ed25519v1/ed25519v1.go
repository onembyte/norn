// Package ed25519v1 is SPEC §3.1's NORN-ED25519-v1: the one Ed25519
// verification predicate every Norn verifier applies (D-072 (c)).
//
// RFC 8032 permits two verification equations and leaves non-canonical
// encodings and points of small order to the implementation, and libraries
// differ exactly there. Go's crypto/ed25519 is cofactorless, refuses S >= L
// and a non-canonical R, and accepts small-order and mixed-order keys; the
// reference's libsodium refuses small-order points but checks a different
// equation. A transparency log is two verifiers agreeing about the state, so
// this package names one answer: every point is the canonical encoding of a
// point of order exactly L, S is below L, and the cofactorless equation holds
// -- under which the cofactored equation gives the same answer, so no
// conforming verifier can disagree with another about any signature.
package ed25519v1

import (
	"bytes"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// lMinusOne is L - 1 as a canonical scalar, little-endian. [L]P is computed
// as [L-1]P + P, because L itself is 0 as a scalar.
var lMinusOne = mustScalar([]byte{
	0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
})

func mustScalar(b []byte) *edwards25519.Scalar {
	s, err := edwards25519.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		panic(err)
	}
	return s
}

// point decodes b as §3.1 item 1's valid point, or reports false: a
// canonical encoding, of a point of order exactly L.
func point(b []byte) (*edwards25519.Point, bool) {
	p, ok := decodeCanonical(b)
	if !ok || !primeOrder(p) {
		return nil, false
	}
	return p, true
}

// decodeCanonical decodes b only if it is the one encoding of its point: the
// bytes decode and re-encode to themselves. SetBytes accepts y >= p and a
// negative zero x, as most of the ecosystem does; re-encoding refuses both.
//
// For a point that also passes primeOrder this check is implied -- a
// non-canonical encoding needs y < 19, and no such point has order L, which
// TestNoNonCanonicalEncodingIsOfPrimeOrder checks exhaustively -- so it is
// defence in depth, and it is why the CCTV set's non_canonical vectors are
// refused by the order check as well.
func decodeCanonical(b []byte) (*edwards25519.Point, bool) {
	if len(b) != 32 {
		return nil, false
	}
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil || !bytes.Equal(p.Bytes(), b) {
		return nil, false
	}
	return p, true
}

// primeOrder reports whether p has order exactly L: not the identity, and
// killed by L. A point with a component of order 2, 4 or 8 is not, even when
// its other component is a perfectly good key: that is the point the two
// verification equations disagree about, and no honest key [s]B or honest
// R = [r]B has one.
func primeOrder(p *edwards25519.Point) bool {
	identity := edwards25519.NewIdentityPoint()
	if p.Equal(identity) == 1 {
		return false
	}
	l := new(edwards25519.Point).ScalarMult(lMinusOne, p)
	return l.Add(l, p).Equal(identity) == 1
}

// ValidPoint reports whether b is a key §3.1 admits: the canonical encoding
// of a point of order exactly L. Every key that enters a state or a trust
// file is checked with it (§3.1 item 2).
func ValidPoint(b []byte) bool {
	_, ok := point(b)
	return ok
}

// Verify reports whether sig is a NORN-ED25519-v1 signature by publicKey over
// message: PureEdDSA, no context, both points valid, S below L, and
// [S]B = R + [k]A.
func Verify(publicKey, message, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	a, ok := point(publicKey)
	if !ok {
		return false
	}
	r, ok := point(sig[:32])
	if !ok {
		return false
	}
	// SetCanonicalBytes refuses S >= L: below L, not reduced, not merely
	// with its top bits clear.
	s, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}
	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey)
	h.Write(message)
	k, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		return false
	}
	// [S]B - [k]A, compared with R as a point; R is canonical, so comparing
	// encodings would say the same.
	minusA := new(edwards25519.Point).Negate(a)
	check := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(k, minusA, s)
	return check.Equal(r) == 1
}
