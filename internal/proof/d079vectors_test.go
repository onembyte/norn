package proof

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/refusal"
)

func TestD079ShippedBundleLabelsAndUndecodableRequestsHaveTheirCodes(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var manifest struct {
		Cases []struct{ Name string }
		Codes map[string]string
	}
	if err := json.Unmarshal(read(t, "proofs-bad/cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, code string }{{"device-not-a-device-id", "bundle"}, {"request-undecodable", "binding"}} {
		t.Run(c.name, func(t *testing.T) {
			found := false
			for _, listed := range manifest.Cases {
				found = found || listed.Name == c.name
			}
			if !found || manifest.Codes[c.name] != c.code {
				t.Error("case must be listed with code " + c.code)
			}
			// A verifier that refuses every bundle must fail the sound side of
			// each pair, even when the malformed request names no sound subject.
			sound := read(t, "proofs/nas.bundle")
			good, err := Decode(sound)
			if err != nil {
				t.Fatal(err)
			}
			if err := good.Check(shippedAnchor(t)); err != nil {
				t.Fatal(err)
			}
			raw := read(t, "proofs-bad/"+c.name+".bundle")
			b, err := Decode(raw)
			if err == nil {
				err = b.Check(shippedAnchor(t))
			}
			code, _ := refusal.CodeOf(err)
			if string(code) != c.code {
				t.Fatalf("Go answers %q (%v), SPEC states %s", code, err, c.code)
			}
			t.Logf("proofs-bad/%s: %s; proofs/nas.bundle: accept", c.name, code)
			if c.name == "device-not-a-device-id" {
				value, err := cbor.DecodeWithin(raw, MaxBundleBytes)
				if err != nil {
					t.Fatal(err)
				}
				m := value.(map[string]any)
				if m["device"] != "NAS" {
					t.Fatal("the malformed label must be NAS")
				}
				m["device"] = "nas"
				repaired, err := cbor.Encode(m)
				if err != nil || !bytes.Equal(repaired, sound) {
					t.Fatalf("restoring the label must recover nas.bundle: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "does not decode") {
					t.Fatalf("binding must follow request decoding: %v", err)
				}
				if b.Index != 79 || b.Device != "probe" || !bytes.Equal(b.Entry, read(t, "log/79-bad-device_id-uppercase.cbor")) || b.Checkpoint != string(read(t, "served/checkpoint")) {
					t.Fatal("the bundle must prove fixture entry 79 under probe and the served head")
				}
			}
		})
	}
}
