// Package bech32m implements BIP-350, the text form of an enrollment request
// (SPEC §16.2).
//
// Why this encoding at all: a device has to hand a signer ~150 bytes across a
// room, and the only channel every phone has is a camera. bech32m is
// case-insensitive, has a strong checksum, and its alphabet fits QR
// alphanumeric mode -- which is exactly that job.
//
// Two rules from the BIP are deliberately not adopted, both SPEC §16.2
// decisions: the 90-character limit, which is sized for addresses, and any
// acceptance of plain bech32, whose only difference is the checksum constant.
package bech32m

import (
	"fmt"
	"strings"
)

const (
	// Charset is the 5-bit alphabet, index = value.
	Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	// Constant distinguishes bech32m from bech32, whose constant is 1.
	Constant = 0x2bc830a3

	separator   = '1'
	checksumLen = 6

	hrpMin = 33 // printable ASCII: anything else is not a human-readable part
	hrpMax = 126
)

var generator = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i, g := range generator {
			if (top>>uint(i))&1 == 1 {
				chk ^= g
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, 2*len(hrp)+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func checksum(hrp string, data []byte) []byte {
	values := append(hrpExpand(hrp), data...)
	values = append(values, make([]byte, checksumLen)...)
	mod := polymod(values) ^ Constant
	out := make([]byte, checksumLen)
	for i := range out {
		out[i] = byte(mod>>(5*uint(5-i))) & 31
	}
	return out
}

// EncodeRaw encodes 5-bit groups under a lowercase printable-ASCII hrp.
func EncodeRaw(hrp string, data []byte) (string, error) {
	if hrp == "" {
		return "", fmt.Errorf("bech32m: empty human-readable part")
	}
	for i := 0; i < len(hrp); i++ {
		c := hrp[i]
		if c < hrpMin || c > hrpMax {
			return "", fmt.Errorf("bech32m: human-readable part character out of range: %q", c)
		}
		if c >= 'A' && c <= 'Z' {
			return "", fmt.Errorf("bech32m: the human-readable part must be lowercase")
		}
	}
	for _, v := range data {
		if v > 31 {
			return "", fmt.Errorf("bech32m: data groups must be 5-bit values")
		}
	}

	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte(separator)
	for _, v := range append(append([]byte(nil), data...), checksum(hrp, data)...) {
		b.WriteByte(Charset[v])
	}
	return b.String(), nil
}

// DecodeRaw decodes to an hrp and 5-bit groups, checksum verified.
//
// It imposes no length limit: SPEC §16.2 drops BIP-173's 90-character bound.
// Above it the code no longer guarantees detection of four errors -- what
// actually protects a request is its own Ed25519 signature.
func DecodeRaw(text string) (string, []byte, error) {
	for i := 0; i < len(text); i++ {
		if text[i] < hrpMin || text[i] > hrpMax {
			return "", nil, fmt.Errorf("bech32m: character out of range at %d", i)
		}
	}
	lower, upper := strings.ToLower(text), strings.ToUpper(text)
	if text != lower && text != upper {
		return "", nil, fmt.Errorf("bech32m: mixed case")
	}
	text = lower

	pos := strings.LastIndexByte(text, separator)
	if pos < 1 {
		return "", nil, fmt.Errorf("bech32m: no separator, or an empty human-readable part")
	}
	if len(text)-pos-1 < checksumLen {
		return "", nil, fmt.Errorf("bech32m: checksum too short")
	}

	hrp, body := text[:pos], text[pos+1:]
	values := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		idx := strings.IndexByte(Charset, body[i])
		if idx < 0 {
			return "", nil, fmt.Errorf("bech32m: invalid data character %q", body[i])
		}
		values = append(values, byte(idx))
	}
	if polymod(append(hrpExpand(hrp), values...)) != Constant {
		return "", nil, fmt.Errorf("bech32m: checksum mismatch")
	}
	return hrp, values[:len(values)-checksumLen], nil
}

func convertBits(values []byte, from, to uint, pad bool) ([]byte, error) {
	var acc, bits uint
	maxv := byte(1<<to - 1)
	out := make([]byte, 0, len(values)*int(from)/int(to)+1)
	for _, v := range values {
		if uint(v)>>from != 0 {
			return nil, fmt.Errorf("bech32m: value out of range for regrouping")
		}
		acc = acc<<from | uint(v)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits)&maxv)
		}
	}
	switch {
	case pad:
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits))&maxv)
		}
	case bits >= from:
		return nil, fmt.Errorf("bech32m: too much padding")
	case byte(acc<<(to-bits))&maxv != 0:
		return nil, fmt.Errorf("bech32m: non-zero padding")
	}
	return out, nil
}

// Encode encodes bytes: 8-bit groups regrouped to 5, zero-padded.
func Encode(hrp string, payload []byte) (string, error) {
	data, err := convertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}
	return EncodeRaw(hrp, data)
}

// Decode decodes to an hrp and bytes. Padding must be under 5 bits and zero.
func Decode(text string) (string, []byte, error) {
	hrp, data, err := DecodeRaw(text)
	if err != nil {
		return "", nil, err
	}
	payload, err := convertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, payload, nil
}
