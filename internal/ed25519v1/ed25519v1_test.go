package ed25519v1

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/edwards25519"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 8032 §7.1, TEST 1 and TEST 2: honest signatures every verifier
// accepts. The same two the cold verifier's self-test carries.
func TestRFC8032HonestSignaturesVerify(t *testing.T) {
	for _, c := range []struct{ key, msg, sig string }{
		{"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
			"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
		{"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
			"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
	} {
		key, msg, sig := unhex(t, c.key), unhex(t, c.msg), unhex(t, c.sig)
		if !ValidPoint(key) {
			t.Errorf("RFC 8032 key %s… is not a valid point", c.key[:8])
		}
		if !Verify(key, msg, sig) {
			t.Errorf("RFC 8032 signature by %s… does not verify", c.key[:8])
		}
		sig[0] ^= 1
		if Verify(key, msg, sig) {
			t.Errorf("a changed RFC 8032 signature by %s… verifies", c.key[:8])
		}
	}
	// And what Go's signer produces, which is everything this project signs.
	for i := 0; i < 32; i++ {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte{byte(i), 'n', 'o', 'r', 'n'}
		if !ValidPoint(pub) || !Verify(pub, msg, ed25519.Sign(priv, msg)) {
			t.Fatalf("an honest key or signature from crypto/ed25519 is refused (round %d)", i)
		}
	}
}

// §3.1 item 4: the C2SP CCTV set, with the outcome `cases.json` states for
// each vector -- 913 refused for the flag that decides it, number 305
// accepted. A predicate that refused honest signatures would be as wrong as
// one that accepted these.
func TestEveryCCTVVectorGetsItsStatedOutcome(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "ed25519-cctv")
	var vectors []struct {
		Number        int
		Key, Sig, Msg string
	}
	var table struct {
		Cases []struct {
			Number        int
			Outcome, Flag string
		}
	}
	for name, into := range map[string]any{"ed25519vectors.json": &vectors, "cases.json": &table} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatal(err)
		}
	}
	outcome := map[int]string{}
	flag := map[int]string{}
	for _, c := range table.Cases {
		outcome[c.Number], flag[c.Number] = c.Outcome, c.Flag
	}
	if len(vectors) != 914 || len(outcome) != 914 {
		t.Fatalf("%d vectors, %d outcomes; want 914 of each", len(vectors), len(outcome))
	}
	wrong := 0
	for _, v := range vectors {
		got := Verify(unhex(t, v.Key), []byte(v.Msg), unhex(t, v.Sig))
		if want := outcome[v.Number] == "accept"; got != want {
			wrong++
			if wrong <= 10 {
				t.Errorf("vector %d (%s): verified %v, cases.json says %s",
					v.Number, flag[v.Number], got, outcome[v.Number])
			}
		}
	}
	if wrong > 10 {
		t.Errorf("…and %d more", wrong-10)
	}
}

// §3.1 item 3: S MUST be less than L. S + L is the same scalar mod L, so a
// verifier that reduced S, or checked only the top bits, accepts it.
func TestSAtOrAboveLIsRefused(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("norn")
	sig := ed25519.Sign(priv, msg)
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	s := new(big.Int).SetBytes(reverse(sig[32:]))
	s.Add(s, l)
	raised := make([]byte, 64)
	copy(raised, sig[:32])
	copy(raised[32:], reverse(leftPad(s.Bytes(), 32)))
	if Verify(pub, msg, raised) {
		t.Error("a signature with S + L verified; S must be below L, not reduced")
	}
}

// §3.1 item 1: a key with a component of order 8 is not of order exactly L,
// whatever its prime-order part. No CCTV vector carries an honest key plus
// torsion, and it is the case a blocklist of small-order encodings misses.
func TestAKeyWithATorsionComponentIsNotAValidPoint(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := new(edwards25519.Point).SetBytes(unhex(t,
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"))
	if err != nil {
		t.Fatal(err)
	}
	mixed := new(edwards25519.Point).Add(a, torsion).Bytes()
	if ValidPoint(mixed) {
		t.Error("an honest key plus a point of order 8 was admitted as a valid point")
	}
	if ValidPoint(new(edwards25519.Point).Set(edwards25519.NewIdentityPoint()).Bytes()) {
		t.Error("the identity was admitted as a valid point")
	}
	if ValidPoint(pub[:31]) {
		t.Error("31 bytes were admitted as a point")
	}
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func leftPad(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// nonCanonical returns every encoding with y >= p that decodes to a point:
// y + p for y < 19 (the only values for which y + p fits in 255 bits), with
// either sign bit, and the negative-zero x of the points with x = 0.
func nonCanonical(t *testing.T) [][]byte {
	t.Helper()
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	var out [][]byte
	for y := int64(0); y < 19; y++ {
		for _, sign := range []byte{0, 0x80} {
			enc := leftPad(new(big.Int).Add(p, big.NewInt(y)).Bytes(), 32)
			enc = reverse(enc)
			enc[31] |= sign
			if _, err := new(edwards25519.Point).SetBytes(enc); err == nil {
				out = append(out, enc)
			}
		}
	}
	// x = 0 with the sign bit set: the identity and the point of order 2.
	for _, s := range []string{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	} {
		out = append(out, unhex(t, s))
	}
	if len(out) < 10 {
		t.Fatalf("only %d non-canonical encodings found", len(out))
	}
	return out
}

// §3.1 item 1: one encoding per point. Checked on its own, because the order
// check below happens to refuse every point a non-canonical encoding can name.
func TestOnlyTheCanonicalEncodingDecodes(t *testing.T) {
	for _, enc := range nonCanonical(t) {
		if _, ok := decodeCanonical(enc); ok {
			t.Errorf("the non-canonical encoding %x… decoded", enc[:4])
		}
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decodeCanonical(pub); !ok {
		t.Error("an honest key's canonical encoding did not decode")
	}
}

// Why the CCTV set cannot tell the canonical check from the order check: no
// point that a non-canonical encoding can name has order exactly L. Checked
// here over all of them, so the claim in decodeCanonical's comment is a fact
// this suite holds, not one it assumes.
func TestNoNonCanonicalEncodingIsOfPrimeOrder(t *testing.T) {
	for _, enc := range nonCanonical(t) {
		p, err := new(edwards25519.Point).SetBytes(enc)
		if err != nil {
			t.Fatal(err)
		}
		if primeOrder(p) {
			t.Errorf("%x… is a non-canonical encoding of a point of order L", enc[:4])
		}
	}
}
