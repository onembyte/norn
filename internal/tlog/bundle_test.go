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

	framed, err := EncodeBundle(entries)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeBundle(framed)
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

// --- Cold-model gate run 5, defect G9 -----------------------------------
//
// §4.0 allowed an entry of exactly 65536 bytes; §6 frames entries in a
// uint16-length-prefixed bundle, whose largest representable entry is 65535.
// A spec-valid entry could not be served -- and this function did not refuse
// it, it truncated the length to zero and produced a bundle that decodes as
// something else entirely. Silent corruption of the log, reachable through a
// document that permitted the input.

func TestAnEntryTooLargeToFrameIsRefusedRatherThanTruncated(t *testing.T) {
	oversize := make([]byte, 65536)
	if _, err := EncodeBundle([][]byte{oversize}); err == nil {
		t.Fatal("framed a 65536-byte entry: the uint16 length wrapped to zero and the " +
			"bundle now decodes as a different log")
	}
}

func TestTheLargestFrameableEntryIsStillFramed(t *testing.T) {
	largest := make([]byte, 65535)
	raw, err := EncodeBundle([][]byte{largest})
	if err != nil {
		t.Fatalf("refused the largest entry the format can carry: %v", err)
	}
	back, err := DecodeBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 1 || len(back[0]) != 65535 {
		t.Fatalf("round-trip gave %d entries, first of %d bytes", len(back), len(back[0]))
	}
}
