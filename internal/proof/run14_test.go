package proof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/refusal"
)

func checkRunFourteenBundlePair(t *testing.T) {
	t.Run("version before checkpoint signature", func(t *testing.T) {
		root := filepath.Join("..", "..", "testdata", "vectors")
		read := func(path string) []byte {
			t.Helper()
			raw, err := os.ReadFile(filepath.Join(root, path))
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		const name = "wrong-version-and-untrusted-checkpoint"
		var manifest struct{ Codes map[string]string }
		if err := json.Unmarshal(read("proofs-bad/cases.json"), &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.Codes[name] != "bundle" {
			t.Errorf("missing bundle pair code")
		}
		raw := read("proofs-bad/" + name + ".bundle")
		value, err := cbor.DecodeWithin(raw, MaxBundleBytes)
		if err != nil {
			t.Fatal(err)
		}
		m := value.(map[string]any)
		good, err := Decode(read("proofs/nas.bundle"))
		if err != nil {
			t.Fatal(err)
		}
		check := func(want refusal.Code) {
			t.Helper()
			raw, err := cbor.Encode(m)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Decode(raw)
			if err == nil {
				err = b.Check(shippedAnchor(t))
			}
			got, _ := refusal.CodeOf(err)
			if got != want || (want == "" && err != nil) {
				t.Fatalf("Go answers %q (%v), SPEC states %q", got, err, want)
			}
		}
		if m["v"] != uint64(2) {
			t.Fatal("version must be 2")
		}
		check(refusal.Bundle)
		bad := m["checkpoint"]
		m["v"] = uint64(1)
		check(refusal.LogSignature)
		m["v"] = uint64(2)
		m["checkpoint"] = good.Checkpoint
		check(refusal.Bundle)
		m["v"] = uint64(1)
		check("")
		m["checkpoint"] = bad
	})
}
