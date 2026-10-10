// Package fields holds the field constraints of SPEC §2 and §4.0.
//
// These rules govern two wire formats -- entry bodies (§4.3) and enrollment
// requests (§16.1) -- and were on their way to being written twice. Two copies
// of a validation rule is how two implementations drift apart while every test
// on both sides still passes, so replay and enrollreq both call here.
//
// Every function takes the `any` a CBOR decode produces and returns a typed
// value; callers translate the error into whatever their layer calls a
// rejection (replay's reason codes, a request's parse error).
package fields

import (
	"fmt"
	"unicode/utf8"
)

// Limits from SPEC §2 and §4.0.
const (
	MaxDeviceID   = 64
	MaxLabels     = 32
	MaxLabelValue = 256
	KeyLen        = 32
	SigLen        = 64
	MaxUint       = uint64(1)<<63 - 1
)

// DeviceID checks §2: UTF-8, 1-64 bytes, [a-z0-9][a-z0-9.-]*.
func DeviceID(value any) (string, error) {
	id, ok := value.(string)
	if !ok || id == "" {
		return "", fmt.Errorf("device_id must be a non-empty string")
	}
	if len(id) > MaxDeviceID {
		return "", fmt.Errorf("device_id is longer than %d bytes", MaxDeviceID)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if i > 0 {
			ok = ok || c == '.' || c == '-'
		}
		if !ok {
			return "", fmt.Errorf("device_id is not [a-z0-9][a-z0-9.-]*: %q", id)
		}
	}
	return id, nil
}

// Labels checks the optional map of §4.0: 1-32 entries when present, values at most
// 256 bytes. Key length is capped at 23 bytes by the codec itself. A nil value
// means the field was absent, which is allowed, and yields a nil map.
func Labels(value any) (map[string]string, error) {
	if value == nil {
		return nil, nil
	}
	raw, ok := value.(map[string]any)
	if !ok || len(raw) == 0 || len(raw) > MaxLabels {
		return nil, fmt.Errorf("labels must be a map of 1-%d entries", MaxLabels)
	}
	out := make(map[string]string, len(raw))
	for key, v := range raw {
		text, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("label %q is not a string", key)
		}
		if len(text) > MaxLabelValue {
			return nil, fmt.Errorf("label %q is longer than %d bytes", key, MaxLabelValue)
		}
		out[key] = text
	}
	return out, nil
}

// PublicKey checks a 32-byte key. `what` names the field for the error.
func PublicKey(value any, what string) ([]byte, error) {
	return Bytes(value, KeyLen, what)
}

// Signature checks a 64-byte Ed25519 signature.
func Signature(value any) ([]byte, error) {
	return Bytes(value, SigLen, "sig")
}

// Bytes checks a byte string of exactly n bytes.
func Bytes(value any, n int, what string) ([]byte, error) {
	raw, ok := value.([]byte)
	if !ok || len(raw) != n {
		return nil, fmt.Errorf("%s must be %d bytes", what, n)
	}
	return raw, nil
}

// Uint checks a non-negative integer, as the codec produces it.
//
// A CBOR bool is not one. Go's type switch refuses it for free; the reference
// implementation did not, because isinstance(True, int) is true in Python, and
// the two disagreed about whether {"expires": true} is a valid enroll body
// until this package existed.
func Uint(value any, what string) (uint64, error) {
	v, ok := value.(uint64)
	if !ok {
		return 0, fmt.Errorf("%s must be a uint", what)
	}
	if v > MaxUint {
		return 0, fmt.Errorf("%s is out of range", what)
	}
	return v, nil
}

// Text checks a text field under a byte cap, and that it is valid UTF-8.
func Text(value any, maxBytes int, what string) (string, error) {
	s, ok := value.(string)
	if !ok || len(s) > maxBytes {
		return "", fmt.Errorf("%s must be text of at most %d bytes", what, maxBytes)
	}
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%s is not valid UTF-8", what)
	}
	return s, nil
}
