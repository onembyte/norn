package policy_test

import (
	"encoding/hex"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"testing"
)

// Policy text admits both kinds of verifier key through the same point rule.
func TestEveryPolicyVerifierKeyMustBeAValidPoint(t *testing.T) {
	small, err := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []byte{note.AlgEd25519, note.AlgCosignature} {
		for _, honest := range []bool{false, true} {
			key := note.VerifierKeyFor("admission", small, alg)
			if honest {
				key = testVKey("admission", alg)
			}
			text := "log " + key + "\nquorum none\n"
			if alg == note.AlgCosignature {
				text = "witness w " + key + "\nquorum w\n"
			}
			_, err := policy.Parse(text)
			if (err == nil) != honest {
				t.Errorf("algorithm %x, honest %v: %v", alg, honest, err)
			}
		}
	}
}
