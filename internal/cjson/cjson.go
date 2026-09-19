// Package cjson implements the canonical JSON of SPEC.md §14.
//
// The standard library is unusable here: encoding/json HTML-escapes "<", ">"
// and "&", and emits \uXXXX escapes in uppercase. §14.2 forbids both. Either
// would produce a state that no other implementation reproduces, while looking
// entirely reasonable in a terminal.
package cjson

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"
)

// ErrProfile reports a value canonical JSON cannot represent.
var ErrProfile = errors.New("outside the canonical JSON profile")

func profileErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProfile, fmt.Sprintf(format, args...))
}

// Marshal renders a value as canonical JSON, with no trailing newline: callers
// that write a file add the single 0x0A §14.1 requires.
func Marshal(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := write(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func write(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case bool:
		buf.WriteString(strconv.FormatBool(v))
	case uint64:
		buf.WriteString(strconv.FormatUint(v, 10))
	case string:
		return writeString(buf, v)
	case []byte:
		return writeString(buf, hex.EncodeToString(v))
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		return writeObject(buf, v)
	default:
		return profileErrorf("type %T", value)
	}
	return nil
}

func writeObject(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Bytewise over the bare key string, which for UTF-8 is code-point order.
	// This is NOT the CBOR map order of §4.1; the two are independent.
	sort.Strings(keys)

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeString(buf, k); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := write(buf, m[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// escapes is the complete table of §14.2. Every other character, including
// "/", "<", ">", "&", U+007F and everything above it, is emitted verbatim.
var escapes = map[byte]string{
	'"': `\"`, '\\': `\\`, '\b': `\b`, '\t': `\t`,
	'\n': `\n`, '\f': `\f`, '\r': `\r`,
}

func writeString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return profileErrorf("string is not valid UTF-8")
	}
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped, ok := escapes[c]; ok {
			buf.WriteString(escaped)
			continue
		}
		if c < 0x20 {
			fmt.Fprintf(buf, `\u%04x`, c) // lowercase hex, per §14.2
			continue
		}
		buf.WriteByte(c)
	}
	buf.WriteByte('"')
	return nil
}
