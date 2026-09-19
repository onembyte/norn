package fields

import (
	"bytes"
	"strings"
	"testing"
)

func TestDeviceIDAccepted(t *testing.T) {
	for _, id := range []string{"a", "pi-cam", "laptop.local", strings.Repeat("a", 64), "0", "x9-.-9x"} {
		got, err := DeviceID(id)
		if err != nil || got != id {
			t.Errorf("DeviceID(%q) = %q, %v", id, got, err)
		}
	}
}

func TestDeviceIDRejected(t *testing.T) {
	cases := []struct {
		value any
		why   string
	}{
		{"", "empty"},
		{strings.Repeat("a", 65), "over 64 bytes"},
		{"Pi-Cam", "uppercase"},
		{".hidden", "leading dot"},
		{"-lead", "leading dash"},
		{"pi cam", "space"},
		{"pi_cam", "underscore"},
		{"café", "non-ASCII"},
		{[]byte("pi-cam"), "bytes, not text"},
		{nil, "absent"},
		{uint64(7), "not a string"},
	}
	for _, c := range cases {
		if _, err := DeviceID(c.value); err == nil {
			t.Errorf("accepted a device_id that is %s", c.why)
		}
	}
}

func TestLabels(t *testing.T) {
	if got, err := Labels(nil); err != nil || got != nil {
		t.Errorf("absent labels = %v, %v", got, err)
	}
	full := map[string]any{}
	for i := 0; i < MaxLabels; i++ {
		full[string(rune('a'+i))] = "v"
	}
	if _, err := Labels(full); err != nil {
		t.Errorf("32 labels rejected: %v", err)
	}
	if _, err := Labels(map[string]any{"ip": strings.Repeat("x", MaxLabelValue)}); err != nil {
		t.Errorf("a 256-byte value rejected: %v", err)
	}

	tooMany := map[string]any{}
	for i := 0; i <= MaxLabels; i++ {
		tooMany[string(rune('a'+i))] = "v"
	}
	bad := []struct {
		value any
		why   string
	}{
		{tooMany, "33 labels"},
		{map[string]any{"ip": strings.Repeat("x", MaxLabelValue+1)}, "value over 256 bytes"},
		{map[string]any{"ip": strings.Repeat("é", 129)}, "258 bytes in UTF-8, though 129 runes"},
		{map[string]any{"ip": uint64(1)}, "non-string value"},
		{[]any{"ip"}, "not a map"},
	}
	for _, c := range bad {
		if _, err := Labels(c.value); err == nil {
			t.Errorf("accepted labels that are %s", c.why)
		}
	}
}

func TestPublicKeyAndSignature(t *testing.T) {
	pk := bytes.Repeat([]byte{1}, KeyLen)
	if got, err := PublicKey(pk, "pk"); err != nil || !bytes.Equal(got, pk) {
		t.Fatalf("PublicKey = %x, %v", got, err)
	}
	for _, v := range []any{bytes.Repeat([]byte{1}, KeyLen-1), bytes.Repeat([]byte{1}, KeyLen+1), strings.Repeat("a", KeyLen), nil} {
		if _, err := PublicKey(v, "pk"); err == nil {
			t.Errorf("accepted a bad public key: %T", v)
		}
	}

	sig := bytes.Repeat([]byte{2}, SigLen)
	if got, err := Signature(sig); err != nil || !bytes.Equal(got, sig) {
		t.Fatalf("Signature = %x, %v", got, err)
	}
	for _, v := range []any{bytes.Repeat([]byte{2}, SigLen-1), bytes.Repeat([]byte{2}, SigLen+1), nil} {
		if _, err := Signature(v); err == nil {
			t.Errorf("accepted a bad signature: %T", v)
		}
	}
}

// The reference implementation accepted a CBOR bool wherever a uint was
// required, because isinstance(True, int) is true in Python, while this side
// refused it: the two disagreed about `{"expires": true}`. Both now refuse.
func TestUintIsNotABool(t *testing.T) {
	if _, err := Uint(uint64(0), "ts"); err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{true, false, "7", nil, int64(-1), int(3)} {
		if _, err := Uint(v, "ts"); err == nil {
			t.Errorf("accepted %#v as a uint", v)
		}
	}
}

func TestBytesOfFixedLength(t *testing.T) {
	net := bytes.Repeat([]byte{3}, 16)
	if got, err := Bytes(net, 16, "net"); err != nil || !bytes.Equal(got, net) {
		t.Fatalf("Bytes = %x, %v", got, err)
	}
	for _, v := range []any{net[:8], append(net, 0), "sixteen bytes!!!", nil} {
		if _, err := Bytes(v, 16, "net"); err == nil {
			t.Errorf("accepted a bad net: %T", v)
		}
	}
}
