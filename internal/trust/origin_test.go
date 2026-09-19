package trust

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestNetFromOriginRoundTrips(t *testing.T) {
	for i := 0; i < 64; i++ {
		net := make([]byte, netLen)
		if _, err := rand.Read(net); err != nil {
			t.Fatal(err)
		}
		origin, err := OriginFor(net)
		if err != nil {
			t.Fatal(err)
		}
		back, err := NetFromOrigin(origin)
		if err != nil {
			t.Fatalf("NetFromOrigin(%q): %v", origin, err)
		}
		if !bytes.Equal(back, net) {
			t.Fatalf("round trip: %x -> %q -> %x", net, origin, back)
		}
	}
}

func TestNetFromOriginAcceptsEitherCase(t *testing.T) {
	net := bytes.Repeat([]byte{0xa5}, netLen)
	origin, err := OriginFor(net)
	if err != nil {
		t.Fatal(err)
	}
	upper := "norn/" + strings.ToUpper(strings.TrimPrefix(origin, "norn/"))
	back, err := NetFromOrigin(upper)
	if err != nil || !bytes.Equal(back, net) {
		t.Fatalf("uppercase origin: %x, %v", back, err)
	}
}

func TestNetFromOriginRejections(t *testing.T) {
	good, err := OriginFor(bytes.Repeat([]byte{1}, netLen))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"empty":          "",
		"no prefix":      strings.TrimPrefix(good, "norn/"),
		"wrong prefix":   "nrn/" + strings.TrimPrefix(good, "norn/"),
		"not base32":     "norn/0189!",
		"too few bytes":  "norn/aebagba",
		"too many bytes": good + "aebagbafaydq",
		"padded":         good + "======",
	}
	for why, origin := range cases {
		if _, err := NetFromOrigin(origin); err == nil {
			t.Errorf("accepted an origin that is %s: %q", why, origin)
		}
	}
}
