package cjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Written from SPEC.md §14. Go's encoding/json cannot be used here: it
// HTML-escapes < > and &, and emits \uXXXX in uppercase. Both are forbidden,
// and both would silently produce a state that no other implementation matches.

func TestEscapesExactlyTheSpecifiedCharacters(t *testing.T) {
	cases := map[string]string{
		`"`:    `\"`,
		`\`:    `\\`,
		"\b":   `\b`,
		"\t":   `\t`,
		"\n":   `\n`,
		"\f":   `\f`,
		"\r":   `\r`,
		"\x00": `\u0000`,
		"\x0b": `\u000b`,
		"\x1f": `\u001f`,
	}
	for input, want := range cases {
		got, err := Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"`+want+`"` {
			t.Errorf("Marshal(%q) = %s, want \"%s\"", input, got, want)
		}
	}
}

func TestLeavesEverythingElseVerbatim(t *testing.T) {
	for _, literal := range []string{"/", "<", ">", "&", "\x7f", "ñ", "日本", "🔑", "א"} {
		got, err := Marshal(literal)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"`+literal+`"` {
			t.Errorf("Marshal(%q) = %s; it must be emitted verbatim", literal, got)
		}
	}
}

func TestLowercaseHexInEscapes(t *testing.T) {
	got, _ := Marshal("\x1b")
	if string(got) != `"\u001b"` {
		t.Errorf("got %s, want lowercase hex", got)
	}
	if strings.ContainsAny(string(got), "ABCDEF") {
		t.Error("escape hex must be lowercase")
	}
}

func TestObjectKeysSortByUTF8CodePoint(t *testing.T) {
	// Bytewise over the bare key string -- NOT the CBOR order of §4.1, which
	// would put the shorter key first.
	got, err := Marshal(map[string]any{"aa": uint64(1), "b": uint64(2)})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"aa":1,"b":2}` {
		t.Errorf("got %s, want {\"aa\":1,\"b\":2}", got)
	}
}

func TestSortingIsRecursiveAndHandlesUnicodeKeys(t *testing.T) {
	got, err := Marshal(map[string]any{
		"outer": map[string]any{"sítio": "x", "a<b&c": "y", "記録": "z", "ip": "w"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"outer":{"a<b&c":"y","ip":"w","sítio":"x","記録":"z"}}`
	if string(got) != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestBytesRenderAsLowercaseHex(t *testing.T) {
	got, err := Marshal(map[string]any{"k": []byte{0xde, 0xad, 0xbe, 0xef}})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"k":"deadbeef"}` {
		t.Errorf("got %s", got)
	}
}

func TestNoWhitespaceAnywhere(t *testing.T) {
	got, err := Marshal(map[string]any{"a": []any{uint64(1), uint64(2)}, "b": true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(string(got), " \t\n") {
		t.Errorf("got %s; canonical JSON carries no whitespace", got)
	}
}

func TestScalarForms(t *testing.T) {
	for value, want := range map[any]string{
		uint64(0): "0", uint64(42): "42", true: "true", false: "false", "": `""`,
	} {
		got, err := Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("Marshal(%v) = %s, want %s", value, got, want)
		}
	}
}

func TestRejectsValuesOutsideTheProfile(t *testing.T) {
	for _, bad := range []any{nil, 1.5, -1, int(3)} {
		if _, err := Marshal(bad); err == nil {
			t.Errorf("Marshal(%v) should have failed", bad)
		}
	}
}

func TestInvalidUTF8IsRejected(t *testing.T) {
	if _, err := Marshal(string([]byte{0xff, 0xfe})); err == nil {
		t.Error("invalid UTF-8 must not be serialised")
	}
}

// The unit tests above are only as good as my reading of §14. This one checks
// against the artifact itself: parse every canonical-JSON file the suite ships,
// re-serialise, and require the bytes back.
func TestReproducesEverySuiteJSONFileByteExact(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	var paths []string
	for _, pattern := range []string{"state.json", "entries/*.json", "genesis/*/state.json",
		"log/manifest.json", "receipt.json", "keys.json"} {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, matches...)
	}
	if len(paths) < 20 {
		t.Fatalf("expected the suite's JSON files, found %d", len(paths))
	}

	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		value, err := parse(bytes.TrimSuffix(raw, []byte{'\n'}))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		again, err := Marshal(value)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if !bytes.Equal(append(again, '\n'), raw) {
			t.Errorf("%s: re-serialised bytes differ from the file", path)
		}
	}
}

// parse reads JSON into the shapes Marshal accepts: numbers as uint64 rather
// than float64, which the standard decoder would otherwise impose.
func parse(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	return convert(generic)
}

func convert(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		n, err := strconv.ParseUint(v.String(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("number %s is not an unsigned integer: %w", v, err)
		}
		return n, nil
	case string, bool:
		return v, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			converted, err := convert(item)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			converted, err := convert(item)
			if err != nil {
				return nil, err
			}
			out[k] = converted
		}
		return out, nil
	}
	return nil, fmt.Errorf("unexpected JSON value %T", value)
}
