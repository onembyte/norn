package enrollreq

import (
	"crypto/sha512"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/edwards25519"
	"github.com/onembyte/norn/internal/bech32m"
	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/ed25519v1"
)

// A torsion R must distinguish the two equations, rather than be a forgery
// every verifier refuses. The equation is checked independently of Norn.
func TestTheTorsionRequestPassesOnlyTheCofactoredEquation(t *testing.T) {
	text, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", "torsion-R-signature.txt"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeText(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := Preimage(req)
	if err != nil {
		t.Fatal(err)
	}
	a, err := new(edwards25519.Point).SetBytes(req.DevicePK)
	if err != nil {
		t.Fatal(err)
	}
	r, err := new(edwards25519.Point).SetBytes(req.Sig[:32])
	if err != nil {
		t.Fatal(err)
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(req.Sig[32:])
	if err != nil {
		t.Fatal(err)
	}
	h := sha512.New()
	h.Write(req.Sig[:32])
	h.Write(req.DevicePK)
	h.Write(msg)
	k, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	diff := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(k, new(edwards25519.Point).Negate(a), s)
	diff.Subtract(diff, r)
	identity := edwards25519.NewIdentityPoint()
	if diff.Equal(identity) == 1 {
		t.Fatal("cofactorless equation holds; R no longer separates the verifiers")
	}
	for i := 0; i < 3; i++ {
		diff.Add(diff, diff)
	}
	if diff.Equal(identity) != 1 {
		t.Fatal("cofactored equation fails; this is merely a forgery")
	}
	if ed25519v1.ValidPoint(req.Sig[:32]) {
		t.Fatal("torsion R passed the point gate")
	}
	if Verify(req) {
		t.Fatal("NORN-ED25519-v1 accepted a torsion R")
	}
}

// §3.1 item 2: the bech32m wrapper and the CBOR are sound, so only the
// device_pk's admission can refuse this request -- and it does so at decode.
func TestTheSmallOrderRequestKeyIsRefusedAtDecode(t *testing.T) {
	text, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", "small-order-device-pk.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// The wrapper and CBOR must be valid so only key admission refuses it.
	_, raw, err := bech32m.Decode(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cbor.Decode(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(raw); err == nil {
		t.Fatal("small-order device_pk decoded")
	}
}

// §3.1 item 3: S + L is the honest scalar's residue, so a verifier that
// reduced S would accept it; reducing S here repairs it and nothing else does.
func TestTheRaisedScalarRequestDoesNotVerify(t *testing.T) {
	text, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", "S-plus-L-signature.txt"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeText(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := edwards25519.NewScalar().SetCanonicalBytes(req.Sig[32:]); err == nil {
		t.Fatal("S is below L; this is not the boundary vector")
	}
	if Verify(req) {
		t.Fatal("S + L request verified")
	}
	// Reduction must recover the honest signature, without repairing any field.
	wide := make([]byte, 64)
	copy(wide, req.Sig[32:])
	reduced, err := edwards25519.NewScalar().SetUniformBytes(wide)
	if err != nil {
		t.Fatal(err)
	}
	copy(req.Sig[32:], reduced.Bytes())
	if !Verify(req) {
		t.Fatal("reducing S alone did not repair the signature")
	}
}
