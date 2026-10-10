package ed25519v1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/edwards25519"
)

// §3.1 item 4 names the clause behind each CCTV flag: non_canonical and
// low_order are "not a valid point", low_order_component is "not of order
// exactly L". This traces every flag on every vector to the check that
// refuses the flagged component, and every unflagged component to the check
// that admits it. It is about which check decides, not the order they run in:
// cases.json's `flag` is the first flag in §3.1's listing, while Verify looks
// at A before R, and a vector whose deciding flag is non_canonical_R may fall
// to A's order check first. Either way the named clause refuses it.
func TestEveryCCTVFlagTracesToTheClauseThatRefusesIt(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "ed25519-cctv")
	var vectors []struct {
		Number   int
		Key, Sig string
		Flags    []string
	}
	var table struct {
		Cases []struct {
			Number int
			Flag   string
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
	deciding := map[int]string{}
	for _, c := range table.Cases {
		deciding[c.Number] = c.Flag
	}
	identity := edwards25519.NewIdentityPoint()
	for _, v := range vectors {
		flags := map[string]bool{}
		for _, f := range v.Flags {
			flags[f] = true
		}
		sig := unhex(t, v.Sig)
		for side, b := range map[string][]byte{"A": unhex(t, v.Key), "R": sig[:32]} {
			nonCanonical, lowOrder, component := flags["non_canonical_"+side],
				flags["low_order_"+side], flags["low_order_component_"+side]
			// Item 1's first clause: the one encoding of its point.
			if _, canonical := decodeCanonical(b); canonical == nonCanonical {
				t.Errorf("vector %d %s: non_canonical=%v but decodeCanonical accepted=%v",
					v.Number, side, nonCanonical, canonical)
			}
			// The point behind the bytes, canonical or not: every CCTV encoding
			// decodes, which is what makes the set a test of the checks after
			// decoding rather than of the decoder.
			p, err := new(edwards25519.Point).SetBytes(b)
			if err != nil {
				t.Fatalf("vector %d %s does not decode: %v", v.Number, side, err)
			}
			// Item 1's "not the identity and no component of order 2, 4 or 8":
			// a low-order point is killed by the cofactor; a point with a
			// low-order component is anything of order not exactly L except the
			// identity, which the README flags low_order alone.
			small := new(edwards25519.Point).MultByCofactor(p).Equal(identity) == 1
			if small != lowOrder {
				t.Errorf("vector %d %s: low_order=%v but [8]P = O is %v", v.Number, side, lowOrder, small)
			}
			isIdentity := p.Equal(identity) == 1
			if hasComponent := !primeOrder(p) && !isIdentity; hasComponent != component {
				t.Errorf("vector %d %s: low_order_component=%v but order-L check says component=%v",
					v.Number, side, component, hasComponent)
			}
			if valid := ValidPoint(b); valid != !(nonCanonical || lowOrder || component) {
				t.Errorf("vector %d %s: flags %v but ValidPoint=%v", v.Number, side, v.Flags, valid)
			}
		}
		// The two auxiliary flags describe the equation's behaviour on a point
		// item 1 already refuses; neither ever decides a case on its own.
		if flags["low_order_residue"] && !flags["low_order_component_A"] && !flags["low_order_component_R"] {
			t.Errorf("vector %d: low_order_residue without a low-order component", v.Number)
		}
		if flags["reencoded_k"] && !flags["non_canonical_A"] && !flags["non_canonical_R"] {
			t.Errorf("vector %d: reencoded_k without a non-canonical encoding", v.Number)
		}
		if f := deciding[v.Number]; f == "low_order_residue" || f == "reencoded_k" {
			t.Errorf("vector %d: cases.json lets %s decide", v.Number, f)
		} else if (f == "") != (len(v.Flags) == 0) {
			t.Errorf("vector %d: flags %v but cases.json's deciding flag is %q", v.Number, v.Flags, f)
		}
	}
}
