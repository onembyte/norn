package cbor

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The property that matters is not "does not panic" -- it is that anything the
// decoder ACCEPTS must re-encode to the identical bytes. A canonical form is
// only canonical if there is exactly one encoding per value, so any input that
// decodes but re-encodes differently is a hole in the profile: two encodings of
// the same value, both accepted, with different hashes and different
// signatures.

func seedFromVectors(f *testing.F) {
	f.Helper()
	for _, dir := range []string{"entries", "log", "trust-bad"} {
		matches, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", dir, "*.cbor"))
		for _, path := range matches {
			if raw, err := os.ReadFile(path); err == nil {
				f.Add(raw)
			}
		}
	}
	// A few hand-built shapes the corpus would take a long time to invent.
	for _, seed := range [][]byte{
		{}, {0x00}, {0xa0}, {0x80}, {0xf5}, {0xf4},
		{0x18, 0x01}, {0x20}, {0xf6}, {0xf9, 0x3c, 0x00}, {0xc1, 0x00},
		{0x9f, 0x01, 0xff}, {0xbf, 0x61, 0x61, 0x01, 0xff}, {0x7f, 0x61, 0x61, 0xff},
		{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x01},
		{0x5a, 0xff, 0xff, 0xff, 0xff},
	} {
		f.Add(seed)
	}
}

func FuzzDecodeIsCanonical(f *testing.F) {
	seedFromVectors(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		value, err := Decode(raw)
		if err != nil {
			return // rejection is always a valid outcome
		}
		again, err := Encode(value)
		if err != nil {
			t.Fatalf("decoded but would not re-encode: %v\ninput: %x", err, raw)
		}
		if !bytes.Equal(raw, again) {
			t.Fatalf("accepted a non-canonical encoding\ninput:  %x\nre-enc: %x", raw, again)
		}
	})
}

func FuzzEncodeDecodeRoundTrip(f *testing.F) {
	f.Add("a", uint64(1), true)
	f.Fuzz(func(t *testing.T, key string, n uint64, flag bool) {
		value := map[string]any{"k": n, "f": flag}
		if len(key) >= 1 && len(key) <= MaxKeyLen {
			value[key] = []byte(key)
		}
		encoded, err := Encode(value)
		if err != nil {
			return // outside the profile is a valid outcome
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("own output rejected: %v", err)
		}
		again, err := Encode(decoded)
		if err != nil || !bytes.Equal(encoded, again) {
			t.Fatalf("round trip is not stable\nfirst:  %x\nsecond: %x", encoded, again)
		}
	})
}
