// Package cbor implements the deterministic CBOR profile of SPEC.md §4.0.
//
// It is deliberately a *strict* decoder as well as a canonical encoder: a
// canonical form is only canonical if non-canonical encodings are refused, so
// every rule the profile states is enforced on the way in. Anything outside the
// profile — floats, tags, negative integers, indefinite lengths, null — is an
// error rather than a value this package knows how to represent.
package cbor

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"
)

// Profile limits from SPEC.md §4.0.
const (
	MaxUint       = uint64(math.MaxInt64) // 2**63 - 1
	MaxKeyLen     = 23
	MaxDepth      = 8
	MaxEntryBytes = 65535
)

// Major types this profile admits.
const (
	mtUint   = 0
	mtBytes  = 2
	mtText   = 3
	mtArray  = 4
	mtMap    = 5
	mtSimple = 7
)

const (
	simpleFalse = 20
	simpleTrue  = 21
)

// ErrProfile is returned for any value or encoding outside the profile.
var ErrProfile = errors.New("outside the Norn CBOR profile")

func profileErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProfile, fmt.Sprintf(format, args...))
}

func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 0x100:
		return []byte{major<<5 | 24, byte(n)}
	case n < 0x10000:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	case n < 0x100000000:
		return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		out := []byte{major<<5 | 27}
		for shift := 56; shift >= 0; shift -= 8 {
			out = append(out, byte(n>>uint(shift)))
		}
		return out
	}
}

// Encode writes a value in the deterministic profile.
//
// Accepted Go types are uint64, []byte, string, bool, []any and
// map[string]any — the shapes the Norn schemas use. Anything else, including
// signed and floating-point numbers, is outside the profile by construction.
func Encode(value any) ([]byte, error) {
	switch v := value.(type) {
	case bool:
		if v {
			return []byte{mtSimple<<5 | simpleTrue}, nil
		}
		return []byte{mtSimple<<5 | simpleFalse}, nil
	case uint64:
		if v > MaxUint {
			return nil, profileErrorf("integer above 2**63-1")
		}
		return head(mtUint, v), nil
	case []byte:
		return append(head(mtBytes, uint64(len(v))), v...), nil
	case string:
		if !utf8.ValidString(v) {
			return nil, profileErrorf("text string is not valid UTF-8")
		}
		return append(head(mtText, uint64(len(v))), v...), nil
	case []any:
		out := head(mtArray, uint64(len(v)))
		for _, item := range v {
			encoded, err := Encode(item)
			if err != nil {
				return nil, err
			}
			out = append(out, encoded...)
		}
		return out, nil
	case map[string]any:
		return encodeMap(v)
	default:
		return nil, profileErrorf("type %T is outside the profile", value)
	}
}

func encodeMap(m map[string]any) ([]byte, error) {
	type pair struct{ key, value []byte }
	pairs := make([]pair, 0, len(m))
	for k, v := range m {
		if n := len(k); n < 1 || n > MaxKeyLen {
			return nil, profileErrorf("map key must be 1-%d bytes, got %d", MaxKeyLen, n)
		}
		key, err := Encode(k)
		if err != nil {
			return nil, err
		}
		value, err := Encode(v)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, pair{key, value})
	}
	// Bytewise over the ENCODED key, per §4.1 — not over the bare string.
	sort.Slice(pairs, func(i, j int) bool {
		return string(pairs[i].key) < string(pairs[j].key)
	})
	out := head(mtMap, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(out, p.key...)
		out = append(out, p.value...)
	}
	return out, nil
}

type decoder struct {
	buf   []byte
	pos   int
	depth int
}

// Decode reads exactly one value, rejecting anything non-canonical or outside
// the profile, and refusing trailing bytes.
func Decode(raw []byte) (any, error) {
	return DecodeWithin(raw, MaxEntryBytes)
}

// DecodeWithin decodes with the caller's own size bound.
//
// §4.0's `MAX_ENTRY_BYTES` is §6's uint16 entry framing, and it belongs to
// entries: a proof bundle *wraps* an entry and is necessarily larger, so a
// decoder that applied one cap everywhere refused a bundle the protocol
// requires it to accept. Every artifact states its own bound; none goes
// unbounded, because that is what the cap is for.
func DecodeWithin(raw []byte, max int) (any, error) {
	if len(raw) > max {
		return nil, profileErrorf("input exceeds %d bytes", max)
	}
	d := &decoder{buf: raw}
	value, err := d.value()
	if err != nil {
		return nil, err
	}
	if d.pos != len(raw) {
		return nil, profileErrorf("trailing bytes")
	}
	return value, nil
}

func (d *decoder) take(n uint64) ([]byte, error) {
	if n > uint64(len(d.buf)-d.pos) {
		return nil, profileErrorf("truncated")
	}
	out := d.buf[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return out, nil
}

func (d *decoder) head() (byte, uint64, error) {
	initial, err := d.take(1)
	if err != nil {
		return 0, 0, err
	}
	major, extra := initial[0]>>5, initial[0]&0x1f
	if extra < 24 {
		return major, uint64(extra), nil
	}
	if extra > 27 {
		return 0, 0, profileErrorf("reserved or indefinite length")
	}
	// Major 7 with a 1-byte argument is a simple value in the two-byte form,
	// which RFC 8949 §3.3 makes not well-formed below 32 -- `false` and `true`
	// included (cold gate run 16, M1). With a 2-, 4- or 8-byte argument it is a
	// float. §4.0 bans floats by name, so the refusal says so: "simple value
	// 15360" is the same sentence a null produces, and `entries-hostile` asks
	// each case to be refused for its own rule (cold gate run 8, D15).
	if major == mtSimple && extra == 24 {
		raw, err := d.take(1)
		if err != nil {
			return 0, 0, err
		}
		if raw[0] < 32 {
			return 0, 0, profileErrorf("simple value %d in the two-byte form is not well-formed (RFC 8949 §3.3)", raw[0])
		}
		return major, uint64(raw[0]), nil
	}
	if major == mtSimple {
		return 0, 0, profileErrorf("floats are outside the profile")
	}
	size := uint64(1) << (extra - 24)
	raw, err := d.take(size)
	if err != nil {
		return 0, 0, err
	}
	var n uint64
	for _, b := range raw {
		n = n<<8 | uint64(b)
	}
	minimum := [...]uint64{24, 0x100, 0x10000, 0x100000000}[extra-24]
	if n < minimum {
		return 0, 0, profileErrorf("non-shortest length encoding")
	}
	return major, n, nil
}

func (d *decoder) value() (any, error) {
	major, n, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case mtUint:
		if n > MaxUint {
			return nil, profileErrorf("integer above 2**63-1")
		}
		return n, nil
	case mtBytes:
		raw, err := d.take(n)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), raw...), nil
	case mtText:
		raw, err := d.take(n)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(raw) {
			return nil, profileErrorf("text string is not valid UTF-8")
		}
		return string(raw), nil
	case mtArray, mtMap:
		d.depth++
		if d.depth > MaxDepth {
			return nil, profileErrorf("nesting deeper than %d", MaxDepth)
		}
		defer func() { d.depth-- }()
		return d.container(major, n)
	case mtSimple:
		switch n {
		case simpleTrue:
			return true, nil
		case simpleFalse:
			return false, nil
		}
		return nil, profileErrorf("simple value %d is outside the profile", n)
	}
	return nil, profileErrorf("major type %d is outside the profile", major)
}

func (d *decoder) container(major byte, n uint64) (any, error) {
	if major == mtArray {
		out := make([]any, 0, min(n, 64))
		for i := uint64(0); i < n; i++ {
			item, err := d.value()
			if err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		return out, nil
	}
	out := make(map[string]any, min(n, 64))
	var previous []byte
	for i := uint64(0); i < n; i++ {
		start := d.pos
		key, err := d.value()
		if err != nil {
			return nil, err
		}
		encoded := d.buf[start:d.pos]
		text, ok := key.(string)
		if !ok {
			return nil, profileErrorf("map key must be a text string")
		}
		if len(text) < 1 || len(text) > MaxKeyLen {
			return nil, profileErrorf("map key must be 1-%d bytes", MaxKeyLen)
		}
		if previous != nil && string(encoded) <= string(previous) {
			return nil, profileErrorf("map keys out of order or duplicated")
		}
		previous = encoded
		value, err := d.value()
		if err != nil {
			return nil, err
		}
		out[text] = value
	}
	return out, nil
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
