package genesis

import (
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"filippo.io/edwards25519"
)

// notValidPoints: a point of order 8, and an honest key with it added -- the
// small-order and mixed-order keys SPEC §3.1 item 1 refuses.
func notValidPoints(t *testing.T, honest []byte) map[string][]byte {
	t.Helper()
	small, err := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := new(edwards25519.Point).SetBytes(small)
	if err != nil {
		t.Fatal(err)
	}
	a, err := new(edwards25519.Point).SetBytes(honest)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"small-order": small,
		"mixed-order": new(edwards25519.Point).Add(a, torsion).Bytes(),
	}
}

// asked is a root key that counts the signatures it is asked for -- a
// hardware token's touch, at a real ceremony.
type asked struct {
	crypto.Signer
	count *int
}

func (a asked) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	*a.count++
	return a.Signer.Sign(rand, digest, opts)
}

// §3.1 item 2: the ceremony refuses, by role, a root, signer, log or witness
// key that is not a valid point, before any root is asked to sign. Replay and
// trust.Validate refuse such a key too, but only after the roots have signed a
// genesis that will never be used.
func TestACeremonyAdmitsOnlyValidPoints(t *testing.T) {
	base, rootPrivs := aCeremony(t)
	var touches int
	sign := []crypto.Signer{asked{rootPrivs[0], &touches}, asked{rootPrivs[1], &touches}}
	if _, err := Build(base, sign); err != nil || touches == 0 {
		t.Fatalf("the honest ceremony: %v, %d signatures; the test shows nothing", err, touches)
	}
	for kind, bad := range notValidPoints(t, base.Signers[0]) {
		root, signer, log, witness := base, base, base, base
		root.Roots = []ed25519.PublicKey{base.Roots[0], base.Roots[1], bad}
		signer.Signers = []ed25519.PublicKey{bad}
		log.LogKey = bad
		witness.Witnesses = []Witness{{Name: base.Witnesses[0].Name, Key: bad, URL: base.Witnesses[0].URL}}
		for slot, c := range map[string]Ceremony{"root": root, "signer": signer, "log": log, "witness": witness} {
			touches = 0
			_, err := Build(c, sign)
			if err == nil || !strings.Contains(err.Error(), "valid point") || !strings.Contains(err.Error(), slot) {
				t.Errorf("a %s %s key: %v, want a refusal naming the %s and the valid-point rule", kind, slot, err, slot)
			}
			if touches != 0 {
				t.Errorf("a %s %s key: the roots were asked for %d signatures before the refusal", kind, slot, touches)
			}
		}
	}
}
