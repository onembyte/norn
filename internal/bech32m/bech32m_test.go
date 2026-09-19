package bech32m

import (
	"bytes"
	"strings"
	"testing"
)

// BIP-350, "Test vectors for Bech32m". Not ours: an encoder and a decoder that
// agree with each other prove only self-consistency.
var bip350Valid = []string{
	"A1LQFN3A",
	"a1lqfn3a",
	"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
	"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
	"11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
	"split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
	"?1v759aa",
}

var bip350Invalid = []struct{ s, why string }{
	{"\x201xj0phk", "HRP character out of range"},
	{"\x7f1g6xzxy", "HRP character out of range"},
	{"\x801vctc34", "HRP character out of range"},
	{tooLong, "overall max length exceeded"},
	{"qyrz8wqd2c9m", "no separator character"},
	{"1qyrz8wqd2c9m", "empty HRP"},
	{"y1b0jsk6g", "invalid data character"},
	{"lt1igcx5c0", "invalid data character"},
	{"in1muywd", "too short checksum"},
	{"mm1crxm3i", "invalid character in checksum"},
	{"au1s5cgom", "invalid character in checksum"},
	{"M1VUXWEZ", "checksum calculated with uppercase form of HRP"},
	{"16plkw9", "empty HRP"},
	{"1p2gdwpf", "empty HRP"},
}

// BIP-173's valid *bech32* strings: every one must fail here, because the two
// encodings differ only in the checksum constant.
var bip173ValidBech32 = []string{
	"A12UEL5L",
	"a12uel5l",
	"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
	"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
	"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
	"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
	"?1ezyfcl",
}

const (
	tooLong       = "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4"
	bip173MaxLen  = 90
	overLongIsBad = "overall max length exceeded"
)

func TestPublishedValidVectorsRoundTrip(t *testing.T) {
	for _, s := range bip350Valid {
		hrp, data, err := DecodeRaw(s)
		if err != nil {
			t.Fatalf("DecodeRaw(%q): %v", s, err)
		}
		got, err := EncodeRaw(hrp, data)
		if err != nil {
			t.Fatalf("EncodeRaw(%q): %v", hrp, err)
		}
		if want := strings.ToLower(s); got != want {
			t.Errorf("round trip = %q, want %q", got, want)
		}
	}
}

func TestPublishedInvalidVectorsRejected(t *testing.T) {
	for _, c := range bip350Invalid {
		if c.why == overLongIsBad {
			continue // see TestTheOneRuleNornDrops
		}
		if _, _, err := DecodeRaw(c.s); err == nil {
			t.Errorf("accepted an invalid vector (%s)", c.why)
		}
	}
}

// SPEC §16.2 drops BIP-173's 90-character limit, and only that: asserted
// narrowly, so every other invalid vector above must still fail.
func TestTheOneRuleNornDrops(t *testing.T) {
	hrp, data, err := DecodeRaw(tooLong)
	if err != nil {
		t.Fatalf("an over-long string must still decode: %v", err)
	}
	if len(tooLong) <= bip173MaxLen {
		t.Fatalf("the vector is not actually over the limit")
	}
	if got, _ := EncodeRaw(hrp, data); got != tooLong {
		t.Errorf("round trip = %q", got)
	}
}

func TestPlainBech32Rejected(t *testing.T) {
	for _, s := range bip173ValidBech32 {
		if _, _, err := DecodeRaw(s); err == nil {
			t.Errorf("accepted plain bech32: %q", s)
		}
	}
}

func TestUppercaseAcceptedAndIdentical(t *testing.T) {
	payload := make([]byte, 40)
	for i := range payload {
		payload[i] = byte(i)
	}
	lower, err := Encode("norn", payload)
	if err != nil {
		t.Fatal(err)
	}
	if lower != strings.ToLower(lower) {
		t.Fatalf("Encode produced non-lowercase output: %q", lower)
	}
	hrp, got, err := Decode(strings.ToUpper(lower))
	if err != nil {
		t.Fatalf("uppercase must decode (QR alphanumeric mode): %v", err)
	}
	if hrp != "norn" || !bytes.Equal(got, payload) {
		t.Errorf("uppercase decoded differently: %q %x", hrp, got)
	}
}

func TestMixedCaseRejected(t *testing.T) {
	s, _ := Encode("norn", []byte{1, 2, 3})
	mixed := s[:6] + strings.ToUpper(s[6:])
	if mixed == s || mixed == strings.ToUpper(s) {
		t.Fatal("the test did not produce a mixed-case string")
	}
	if _, _, err := Decode(mixed); err == nil {
		t.Error("accepted mixed case")
	}
}

func TestBytesRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 2, 31, 32, 33, 255, 256} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte((i*7 + 3) % 256)
		}
		s, err := Encode("norn", payload)
		if err != nil {
			t.Fatal(err)
		}
		hrp, got, err := Decode(s)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if hrp != "norn" || !bytes.Equal(got, payload) {
			t.Errorf("n=%d round trip mismatch", n)
		}
	}
}

func TestOneFlippedCharacterCaught(t *testing.T) {
	s, _ := Encode("norn", []byte("payload for a flip test"))
	other := byte('q')
	if s[len(s)-1] == 'q' {
		other = 'p'
	}
	if _, _, err := Decode(s[:len(s)-1] + string(other)); err == nil {
		t.Error("a flipped character survived the checksum")
	}
}

func TestPaddingMustBeZeroAndShort(t *testing.T) {
	s, _ := Encode("norn", []byte{0})
	hrp, data, err := DecodeRaw(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 2 {
		t.Fatalf("8 bits should be two 5-bit groups, got %d", len(data))
	}

	bad := append([]byte(nil), data...)
	bad[len(bad)-1] |= 1 // a non-zero tail is a value pretending to be padding
	nonZero, _ := EncodeRaw(hrp, bad)
	if _, _, err := Decode(nonZero); err == nil {
		t.Error("accepted non-zero padding")
	}

	extra, _ := EncodeRaw(hrp, append(append([]byte(nil), data...), 0))
	if _, _, err := Decode(extra); err == nil {
		t.Error("accepted five bits of padding")
	}
}

func TestHRPIsReturnedNotAssumed(t *testing.T) {
	s, _ := Encode("other", []byte{9})
	hrp, _, err := Decode(s)
	if err != nil || hrp != "other" {
		t.Errorf("hrp = %q, err = %v", hrp, err)
	}
}

func TestEncodeRefusesAnUppercaseHRP(t *testing.T) {
	if _, err := Encode("NORN", []byte{1}); err == nil {
		t.Error("encoded with an uppercase human-readable part")
	}
}
