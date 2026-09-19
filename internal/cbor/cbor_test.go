package cbor

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/bech32m"
)

// Written from SPEC.md §4.0. The vectors are the oracle: every entry in the
// suite must round-trip byte-exact, and every encoding negative must be
// rejected — including the ones that a lenient decoder would happily accept.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestEncodeMatchesRFC8949Examples(t *testing.T) {
	cases := []struct {
		value any
		want  string
	}{
		{uint64(0), "00"}, {uint64(1), "01"}, {uint64(23), "17"},
		{uint64(24), "1818"}, {uint64(255), "18ff"}, {uint64(256), "190100"},
		{uint64(65535), "19ffff"}, {uint64(65536), "1a00010000"},
		{uint64(1) << 32, "1b0000000100000000"},
		{uint64(1)<<63 - 1, "1b7fffffffffffffff"},
		{[]byte{}, "40"}, {[]byte{1, 2, 3, 4}, "4401020304"},
		{"", "60"}, {"a", "6161"}, {"IETF", "6449455446"}, {"ü", "62c3bc"},
		{false, "f4"}, {true, "f5"},
		{[]any{}, "80"}, {[]any{uint64(1), uint64(2), uint64(3)}, "83010203"},
		{map[string]any{}, "a0"},
		{map[string]any{"a": uint64(1), "b": []any{uint64(2), uint64(3)}}, "a26161016162820203"},
	}
	for _, c := range cases {
		got, err := Encode(c.value)
		if err != nil {
			t.Errorf("Encode(%v): %v", c.value, err)
			continue
		}
		if !bytes.Equal(got, mustHex(t, c.want)) {
			t.Errorf("Encode(%v) = %x, want %s", c.value, got, c.want)
		}
	}
}

func TestMapKeysSortByEncodedForm(t *testing.T) {
	// "b" encodes shorter than "aa", so it sorts first — the §4.1 trap.
	got, err := Encode(map[string]any{"aa": uint64(1), "b": uint64(2)})
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "a26162026261610"+"1")
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

func TestEncodeRejectsValuesOutsideTheProfile(t *testing.T) {
	for _, bad := range []any{
		-1, int64(-1), 1.5, nil, uint64(1) << 63,
		map[string]any{"": uint64(1)},
		map[string]any{"012345678901234567890123": uint64(1)}, // 24-byte key
	} {
		if _, err := Encode(bad); err == nil {
			t.Errorf("Encode(%v) should have failed", bad)
		}
	}
}

func TestDecodeRejectsNonCanonicalAndOutOfProfile(t *testing.T) {
	cases := map[string]string{
		"non-shortest uint":   "1801",
		"negative integer":    "20",
		"null":                "f6",
		"undefined":           "f7",
		"float16":             "f97e00",
		"indefinite array":    "9f01ff",
		"indefinite map":      "bf616101ff",
		"indefinite text":     "7f6161ff",
		"tag":                 "c100",
		"integer map key":     "a10102",
		"duplicate map key":   "a2616101616101",
		"unsorted map keys":   "a2616202616101",
		"empty map key":       "a16001",
		"trailing bytes":      "0100",
		"truncated":           "1a0001",
		"reserved additional": "1c",
		"stray break":         "ff",
	}
	for name, h := range cases {
		if _, err := Decode(mustHex(t, h)); err == nil {
			t.Errorf("%s: Decode(%s) should have failed", name, h)
		}
	}
}

func TestDecodeRejectsInvalidUTF8(t *testing.T) {
	if _, err := Decode(mustHex(t, "62c328")); err == nil {
		t.Error("invalid UTF-8 text string should be rejected")
	}
}

func TestResourceLimits(t *testing.T) {
	deep := bytes.Repeat([]byte{0x81}, MaxDepth+1)
	if _, err := Decode(append(deep, 0x00)); err == nil {
		t.Error("nesting beyond MaxDepth should be rejected")
	}
	ok := bytes.Repeat([]byte{0x81}, MaxDepth-1)
	if _, err := Decode(append(ok, 0x00)); err != nil {
		t.Errorf("nesting at MaxDepth should be accepted: %v", err)
	}
	huge := make([]byte, MaxEntryBytes+1)
	if _, err := Decode(huge); err == nil {
		t.Error("input beyond MaxEntryBytes should be rejected")
	}
	// A huge declared length with no payload must fail without allocating.
	if _, err := Decode(mustHex(t, "5affffffff")); err == nil {
		t.Error("truncated length header should be rejected")
	}
}

// Every valid entry the suite ships must decode and re-encode byte-exact.
func TestSuiteEntriesRoundTrip(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	var checked int
	for _, dir := range []string{"entries", "log"} {
		matches, err := filepath.Glob(filepath.Join(root, dir, "*.cbor"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range matches {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			value, err := Decode(raw)
			if err != nil {
				continue // the negatives are supposed to fail; 1.4 checks why
			}
			again, err := Encode(value)
			if err != nil {
				t.Errorf("%s: decoded but would not re-encode: %v", path, err)
				continue
			}
			if !bytes.Equal(raw, again) {
				t.Errorf("%s: re-encode differs from the file", path)
			}
			checked++
		}
	}
	if checked < 80 {
		t.Errorf("only %d entries round-tripped; expected the whole suite", checked)
	}
}

// The round-trip test above skips anything that fails to decode. That would
// pass with a decoder that rejects nothing at all, so name the encoding
// negatives explicitly and require each to fail here, at the CBOR layer,
// before any schema rule could reach it.
func TestSuiteEncodingNegativesAreRejected(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors", "log")
	suffixes := []string{
		"bad-cbor-nonshortest", "bad-cbor-null", "bad-cbor-unsorted-keys",
		"bad-tag-wrapped-value", "bad-indefinite-text", "bad-indefinite-map",
		"bad-duplicate-map-key", "bad-invalid-utf8", "bad-integer-too-large",
		// Not here either: `bad-oversize-map-key` moved to the request
		// vectors when SPEC §4.3 put the device's claims inside the request,
		// because no entry body has a free-form map left to put a 24-byte key
		// in. TestOversizeMapKeyInARequest covers it.
		// Not here: `bad-unsorted-sigs`. CBOR does not canonicalise array
		// order, so "sigs sorted by kid" is a schema rule enforced at replay,
		// not a profile rule the codec could see.
	}
	for _, suffix := range suffixes {
		matches, err := filepath.Glob(filepath.Join(root, "*-"+suffix+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 {
			t.Errorf("%s: expected exactly one vector, found %d", suffix, len(matches))
			continue
		}
		raw, err := os.ReadFile(matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s: decoded successfully; the profile rule it names is not enforced", suffix)
		}
	}
}

// The controls those negatives are patches of must decode cleanly, or a
// negative could be failing for something it inherited from its base.
func TestSuiteControlsDecode(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors", "log")
	for _, suffix := range []string{"profile-base", "labelcap-base", "two-sig-base"} {
		matches, _ := filepath.Glob(filepath.Join(root, "*-"+suffix+".cbor"))
		if len(matches) != 1 {
			t.Errorf("%s: expected exactly one control", suffix)
			continue
		}
		raw, err := os.ReadFile(matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(raw); err != nil {
			t.Errorf("%s: control must decode cleanly, got %v", suffix, err)
		}
	}
}

// TestOversizeMapKeyInARequest keeps §4.0's 23-byte map-key cap under test
// after the vector that carried it moved.
//
// The case lives in `requests-bad/` now: since §4.3 made an `enroll` body the
// device's request, the only free-form map left in the suite is a request's
// `labels`. The rule being checked is unchanged -- this codec must refuse the
// key -- and it matters that the codec refuses it, because a closed-schema
// check would fire first anywhere else and hide a missing cap.
func TestOversizeMapKeyInARequest(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "vectors", "requests-bad",
		"oversize-label-key.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := bech32m.Decode(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("the vector is not decodable bech32m: %v", err)
	}
	if _, err := Decode(payload); err == nil {
		t.Error("decoded a 24-byte map key; the §4.0 cap is not enforced")
	}
}
