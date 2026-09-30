package trust

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/onembyte/norn/internal/cbor"
)

// --- Cold-model gate run 11, defect D6 ----------------------------------
//
// §9.1's two names are 1-64 bytes of UTF-8. `26` and `32` were ASCII, and no
// name sat at 64, so a reader counting characters, or refusing 64, passed.
// Each cap now ships as a pair that differs in one character: an ASCII `x` in
// the positive, a two-byte `Ж` in the negative.

func sameCharactersOneByteOver(t *testing.T, pos, neg string, cap int) {
	t.Helper()
	if len(pos) != cap || len(neg) != cap+1 {
		t.Fatalf("%d and %d bytes; the pair must sit at %d and one past it", len(pos), len(neg), cap)
	}
	p, n := []rune(pos), []rune(neg)
	if len(p) != len(n) || len(utf16.Encode(p)) != len(utf16.Encode(n)) {
		t.Fatalf("the two differ in characters, so a reader counting them can tell them apart")
	}
	var differ int
	for i := range p {
		if p[i] != n[i] {
			differ++
			if utf8.RuneLen(p[i]) != 1 || utf8.RuneLen(n[i]) != 2 {
				t.Errorf("character %d is %q and %q; the swap is ASCII for two bytes", i, p[i], n[i])
			}
		}
	}
	if differ != 1 {
		t.Fatalf("%d characters differ; the pair must differ in exactly one", differ)
	}
	// Measured as encoded (§4.0): normalised first, the positive is over the cap.
	// `é` (U+00E9) is the motif's one decomposable letter: two bytes as sent,
	// three once decomposed, counted here without an x/text dependency.
	if n := len(pos) + strings.Count(pos, "\u00e9"); n <= cap {
		t.Errorf("the positive is %d bytes under NFD, within the cap of %d", n, cap)
	}
}

func decodeVector(t *testing.T, dir, name string) (map[string]any, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), dir, name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatalf("%s/%s does not decode: %v", dir, name, err)
	}
	return value.(map[string]any), raw
}

func TestTheTrustNameCapsCountBytesNotCharacters(t *testing.T) {
	for _, c := range []struct{ pos, neg, refusal string }{
		{"name-at-the-cap", "26-name-too-long", "name must be 1-64 bytes"},
		{"witness-name-at-the-cap", "32-witness-name-too-long", "a witness name must be 1-64 bytes"},
	} {
		t.Run(c.neg, func(t *testing.T) {
			pos, posRaw := decodeVector(t, "trust-good", c.pos)
			neg, negRaw := decodeVector(t, "trust-bad", c.neg)

			// The shape: one name, one byte, and nothing else.
			var posName, negName string
			if c.pos == "name-at-the-cap" {
				posName, _ = pos["name"].(string)
				negName, _ = neg["name"].(string)
				delete(pos, "name")
				delete(neg, "name")
			} else {
				pw := pos["witnesses"].([]any)[0].(map[string]any)
				nw := neg["witnesses"].([]any)[0].(map[string]any)
				posName, _ = pw["name"].(string)
				negName, _ = nw["name"].(string)
				// The policy names the witness too, so correspondence holds.
				if want := strings.ReplaceAll(pos["policy"].(string), posName, negName); neg["policy"] != want {
					t.Error("the negative's policy is not the positive's with the name swapped, " +
						"so the correspondence rule could refuse it")
				}
				delete(pw, "name")
				delete(nw, "name")
				delete(pos, "policy")
				delete(neg, "policy")
			}
			sameCharactersOneByteOver(t, posName, negName, 64)
			if !reflect.DeepEqual(pos, neg) {
				t.Fatal("the two files differ in more than the name")
			}

			// Then the verdicts.
			doc, err := Parse(posRaw)
			if err == nil {
				err = doc.Validate()
			}
			if err != nil {
				t.Errorf("trust-good/%s is refused: %v; it sits exactly at the cap", c.pos, err)
			}
			doc, err = Parse(negRaw)
			if err == nil {
				err = doc.Validate()
			}
			if err == nil || !strings.Contains(err.Error(), c.refusal) {
				t.Errorf("trust-bad/%s: got %v, want a refusal saying %q", c.neg, err, c.refusal)
			}
		})
	}
}
