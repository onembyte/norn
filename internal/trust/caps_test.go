package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
)

// Cold gate run 12, D16. MAX_TRUST_BYTES was pinned only far from the
// boundary -- `38-oversize` is thousands of bytes over -- so a reader whose
// cap was one byte too lax, or one byte too strict, passed. The suite now
// ships a file exactly at the cap, which MUST be accepted, and one exactly a
// byte past it that nothing but its size refuses: lift the cap and it
// decodes.
func TestTheTrustCapIsPinnedFromBothSides(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	files := func(dir string) map[string][]byte {
		out := map[string][]byte{}
		paths, err := filepath.Glob(filepath.Join(root, dir, "*.cbor"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			out[strings.TrimSuffix(filepath.Base(p), ".cbor")] = raw
		}
		return out
	}
	var atTheCap bool
	for name, raw := range files("trust-good") {
		if len(raw) != MaxTrustBytes {
			continue
		}
		if _, err := Parse(raw); err != nil {
			t.Errorf("trust-good/%s is exactly MAX_TRUST_BYTES and refused: %v", name, err)
		}
		atTheCap = true
	}
	if !atTheCap {
		t.Error("no trust-good file is exactly MAX_TRUST_BYTES, so a reader whose cap " +
			"is one byte too strict passes")
	}
	var onePast bool
	for name, raw := range files("trust-bad") {
		if len(raw) != MaxTrustBytes+1 {
			continue
		}
		if _, err := Parse(raw); err == nil {
			t.Errorf("trust-bad/%s is one byte past MAX_TRUST_BYTES and accepted", name)
		}
		if _, err := cbor.DecodeWithin(raw, 4*MaxTrustBytes); err != nil {
			t.Errorf("trust-bad/%s does not decode even with the cap lifted, so its "+
				"size is not the only thing refusing it: %v", name, err)
		}
		onePast = true
	}
	if !onePast {
		t.Error("no trust-bad file is exactly one byte past MAX_TRUST_BYTES, so a " +
			"reader whose cap is one byte too lax passes")
	}
}
