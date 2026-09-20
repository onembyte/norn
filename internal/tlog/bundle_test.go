package tlog

import (
	"bytes"
	"testing"
)

// An entry bundle is `tlog-tiles`' framing: each entry preceded by a
// big-endian uint16 length. One implementation, because a writer and a reader
// that disagree about a malformed bundle disagree about what the log contains.

func TestABundleRoundTrips(t *testing.T) {
	entries := [][]byte{[]byte("one"), {}, bytes.Repeat([]byte("x"), 0xffff)}

	back, err := DecodeBundle(EncodeBundle(entries))
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(entries) {
		t.Fatalf("decoded %d entries, want %d", len(back), len(entries))
	}
	for i := range entries {
		if !bytes.Equal(back[i], entries[i]) {
			t.Errorf("entry %d changed", i)
		}
	}
}

func TestAMalformedBundleIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"one byte of a length prefix", []byte{0x00}},
		{"a length with nothing after it", []byte{0x00, 0x05}},
		{"a length longer than what follows", []byte{0x00, 0x05, 'a', 'b'}},
		{"trailing junk after a good entry", []byte{0x00, 0x01, 'a', 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeBundle(tc.raw); err == nil {
				t.Errorf("%x was accepted", tc.raw)
			}
		})
	}
}

// An empty bundle is empty, not an error: a log with no entries serves none.
func TestAnEmptyBundleDecodesToNothing(t *testing.T) {
	back, err := DecodeBundle(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 0 {
		t.Errorf("decoded %d entries from nothing", len(back))
	}
}
