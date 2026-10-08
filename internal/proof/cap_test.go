package proof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/refusal"
)

// Cold gate run 13, D15. Unlisted cosignatures can grow a checkpoint while
// every bundle check stays valid. Check the extra lines cryptographically,
// then remove only the size restriction to show it is the sole refusal.
func TestTheBundleCapIsPinnedFromBothSides(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	anchor := shippedAnchor(t)
	base, err := Decode(read(t, "proofs/nas.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Ed25519 map[string]struct {
			Public string `json:"public"`
		} `json:"ed25519"`
	}
	if err := json.Unmarshal(read(t, "keys.json"), &keys); err != nil {
		t.Fatal(err)
	}
	public, err := hex.DecodeString(keys.Ed25519["stranger"].Public)
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatalf("stranger public key: %x, %v", public, err)
	}
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		dir, name string
		size      int
		accepted  bool
	}{
		{"proofs", "at-the-cap", 81919, true},
		{"proofs-bad", "one-past-the-cap", 81920, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := read(t, tc.dir+"/"+tc.name+".bundle")
			if len(raw) != tc.size {
				t.Fatalf("%d bytes, want %d", len(raw), tc.size)
			}
			var manifest struct {
				AtTheCap struct {
					File   string `json:"file"`
					Bytes  int    `json:"bytes"`
					Accept bool   `json:"accept"`
				} `json:"at_the_cap"`
				Codes map[string]refusal.Code `json:"codes"`
			}
			if err := json.Unmarshal(read(t, tc.dir+"/cases.json"), &manifest); err != nil {
				t.Fatal(err)
			}
			if tc.accepted {
				if manifest.AtTheCap.File != tc.name+".bundle" || manifest.AtTheCap.Bytes != tc.size || !manifest.AtTheCap.Accept {
					t.Fatal("positive manifest does not require acceptance at the cap")
				}
				b, err := Decode(raw)
				if err != nil {
					t.Fatalf("at-the-cap refused: %v", err)
				}
				if err := b.Check(anchor); err != nil {
					t.Fatal(err)
				}
			} else {
				if manifest.Codes[tc.name] != refusal.Bundle {
					t.Fatal("one-past case is not coded bundle")
				}
				_, err := Decode(raw)
				if got, _ := refusal.CodeOf(err); got != refusal.Bundle {
					t.Fatalf("one-past refused as %q, want bundle: %v", got, err)
				}
			}
			// Decode under this file's length only to inspect the oversize positive
			// twin. Re-encoding through Bundle checks every schema field as well.
			value, err := cbor.DecodeWithin(raw, len(raw))
			if err != nil {
				t.Fatal(err)
			}
			m, ok := value.(map[string]any)
			if !ok {
				t.Fatal("not a map")
			}
			checkpoint, ok := m["checkpoint"].(string)
			if !ok {
				t.Fatal("checkpoint is not text")
			}
			b := *base
			b.Checkpoint = checkpoint
			encoded, err := b.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, encoded) {
				t.Fatal("padding changed more than the checkpoint")
			}
			if err := b.Check(anchor); err != nil {
				t.Fatalf("not otherwise sound: %v", err)
			}
			if !strings.HasPrefix(checkpoint, base.Checkpoint) {
				t.Fatal("original checkpoint was changed")
			}
			body, sigs, err := note.Split(checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			_, original, err := note.Split(base.Checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			if len(sigs) <= len(original) {
				t.Fatal("no extra cosignatures")
			}
			for _, sig := range sigs[len(original):] {
				if _, listed := rules.LabelFor(sig.Name, public); listed {
					t.Fatal("padding witness is listed")
				}
				if !sig.IsCosignature() || !bytes.Equal(sig.KeyID, note.KeyIDFor(sig.Name, public, note.AlgCosignature)) {
					t.Fatal("padding is not a stranger cosignature")
				}
				at := time.Unix(int64(binary.BigEndian.Uint64(sig.Sig[:8])), 0)
				if !ed25519.Verify(public, cosign.Message(at, body), sig.Sig[8:]) {
					t.Fatal("padding cosignature does not verify")
				}
			}
		})
	}
}
