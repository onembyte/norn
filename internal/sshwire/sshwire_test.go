package sshwire

import (
	"bytes"
	"testing"
)

func TestStringRoundTrip(t *testing.T) {
	for _, value := range [][]byte{nil, {}, []byte("ssh-ed25519"), bytes.Repeat([]byte{0xff}, 300)} {
		encoded := AppendString(nil, value)
		got, rest, err := String(encoded)
		if err != nil {
			t.Fatalf("String: %v", err)
		}
		if !bytes.Equal(got, value) {
			t.Errorf("round trip = %x, want %x", got, value)
		}
		if len(rest) != 0 {
			t.Errorf("%d bytes left over", len(rest))
		}
	}
}

func TestStringsInSequence(t *testing.T) {
	buf := AppendString(nil, []byte("one"))
	buf = AppendString(buf, []byte("two"))
	first, rest, err := String(buf)
	if err != nil || string(first) != "one" {
		t.Fatalf("first = %q, %v", first, err)
	}
	second, rest, err := String(rest)
	if err != nil || string(second) != "two" {
		t.Fatalf("second = %q, %v", second, err)
	}
	if len(rest) != 0 {
		t.Errorf("%d bytes left over", len(rest))
	}
}

// A length prefix is attacker-controlled input wherever it comes from -- an
// agent socket, a key file. It must never become a slice bound.
func TestTruncatedInputIsRefused(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"partial length":  {0, 0, 1},
		"length past end": {0, 0, 0, 8, 1, 2, 3},
		"huge length":     {0xff, 0xff, 0xff, 0xff, 1},
	}
	for why, raw := range cases {
		if _, _, err := String(raw); err == nil {
			t.Errorf("accepted %s", why)
		}
	}
}

func TestUint32(t *testing.T) {
	buf := AppendUint32(nil, 0x01020304)
	got, rest, err := Uint32(buf)
	if err != nil || got != 0x01020304 {
		t.Fatalf("Uint32 = %#x, %v", got, err)
	}
	if len(rest) != 0 {
		t.Errorf("%d bytes left over", len(rest))
	}
	if _, _, err := Uint32([]byte{1, 2, 3}); err == nil {
		t.Error("accepted three bytes as a uint32")
	}
}
