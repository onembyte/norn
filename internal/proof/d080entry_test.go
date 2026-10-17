package proof

import (
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
)

// revokeOf is a `revoke` about deviceName padded to exactly size bytes.
func revokeOf(t *testing.T, size int) []byte {
	t.Helper()
	for pad := size - 64; pad > 0; pad-- {
		raw, err := entry.Encode(&entry.Envelope{
			V: entry.Version, T: "revoke", Net: make([]byte, 16), TS: 1,
			Body: map[string]any{"device_id": deviceName, "reason": strings.Repeat("x", pad)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) == size {
			return raw
		}
	}
	t.Fatalf("no padding makes a %d-byte revoke", size)
	return nil
}

// D-080 (5) with cold gate run 17's D7, row 6.5l-xv-h. §8.1 types `entry` as
// an entry, and an entry is at most MAX_ENTRY_BYTES; a bundle around a longer
// one is malformed, `bundle` at step 1, before any checkpoint is read. Go
// decoded it, and a log that committed the oversize leaf in a tree it signed
// carried it through the checkpoint and the inclusion proof to step 4, where
// the entry failed to decode and the answer was `binding`: one structural
// fault refused at step 4 where every other is refused at step 1. The tree
// here commits each entry as such a log would; MaxBundleBytes leaves room for
// both, so only the entry's length differs.
func TestAnEntryOverMaxEntryBytesIsMalformedAtStepOne(t *testing.T) {
	for _, c := range []struct {
		name string
		size int
		want refusal.Code
	}{
		{"exactly MAX_ENTRY_BYTES", cbor.MaxEntryBytes, ""},
		{"one byte over", cbor.MaxEntryBytes + 1, refusal.Bundle},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, key, origin := build(t, 1)
			entries := [][]byte{revokeOf(t, c.size), revokeOf(t, 200)}
			tree, err := tlog.Build(entries)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := tree.Checkpoint(origin).Sign(key)
			if err != nil {
				t.Fatal(err)
			}
			p, err := tree.InclusionProof(0)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := Build(deviceName, 0, entries[0], p, signed)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := bundle.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) > MaxBundleBytes {
				t.Fatalf("the bundle is %d bytes, over MAX_BUNDLE_BYTES; the case tests the cap instead", len(raw))
			}
			back, err := Decode(raw)
			if c.want == "" {
				if err != nil {
					t.Fatalf("a bundle around a %d-byte entry must decode: %v", c.size, err)
				}
				if err := back.Check(testAnchor(t, origin, key)); err != nil {
					t.Fatalf("a sound bundle around a %d-byte entry must check out: %v", c.size, err)
				}
				return
			}
			if err == nil {
				err = back.Check(testAnchor(t, origin, key))
			}
			if got, _ := refusal.CodeOf(err); got != c.want {
				t.Fatalf("a bundle around a %d-byte entry: got %q (%v), want %q at step 1", c.size, got, err, c.want)
			}
		})
	}
}
