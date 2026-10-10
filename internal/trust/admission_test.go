package trust

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"filippo.io/edwards25519"

	"github.com/onembyte/norn/internal/note"
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

// §3.1 item 2, §9: a trust file whose log_key or a witness key is not a valid
// point is invalid. Each case swaps one key everywhere the file names it --
// the field and the policy text -- and the same swap to an honest key
// validates, so what refuses the file is the key's own validity.
func TestATrustFileAdmitsOnlyValidPoints(t *testing.T) {
	good := loadGood(t)
	logKey, err := note.ParseVerifierKey(good.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	witness := good.Witnesses[0]
	witnessKey, err := note.ParseVerifierKey(witness.Key)
	if err != nil {
		t.Fatal(err)
	}
	swaps := map[string]func(public []byte) *Trust{
		"log_key": func(public []byte) *Trust {
			doc := *good
			vkey := note.VerifierKey(logKey.Name, public)
			doc.Policy = strings.ReplaceAll(good.Policy, good.LogKey, vkey)
			doc.LogKey = vkey
			return &doc
		},
		"witness": func(public []byte) *Trust {
			doc := *good
			vkey := note.CosignerVerifierKey(witnessKey.Name, public)
			doc.Witnesses = append([]Witness(nil), good.Witnesses...)
			doc.Witnesses[0].Key = vkey
			doc.Policy = strings.ReplaceAll(good.Policy, witness.Key, vkey)
			return &doc
		},
	}
	honest, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for slot, swap := range swaps {
		if err := swap(honest).Validate(); err != nil {
			t.Fatalf("the %s swapped for an honest key: %v; the test shows nothing", slot, err)
		}
		for kind, bad := range notValidPoints(t, honest) {
			if err := swap(bad).Validate(); err == nil || !strings.Contains(err.Error(), "valid point") {
				t.Errorf("a %s %s: %v, want a refusal under the valid-point rule", kind, slot, err)
			}
		}
	}
}
