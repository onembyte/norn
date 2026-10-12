package entry

import (
	"bytes"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
)

func TestPrevIsOptionalUnsignedAndSigned(t *testing.T) {
	n := uint64(9)
	e := &Envelope{V: Version, T: "note", Net: make([]byte, 16), Body: map[string]any{"text": "x"}}
	before, _ := Preimage(e)
	e.Prev = &n
	after, _ := Preimage(e)
	if bytes.Equal(before, after) {
		t.Error("prev is missing from the signature preimage")
	}
	raw, _ := Encode(e)
	decoded, err := Decode(raw)
	if err != nil || decoded.Prev == nil || *decoded.Prev != n {
		t.Fatalf("prev did not round trip: %v, %+v", err, decoded)
	}
	m, _ := cbor.Decode(raw)
	for _, bad := range []any{"9", true} {
		m.(map[string]any)["prev"] = bad
		b, _ := cbor.Encode(m)
		if _, err := Decode(b); err == nil {
			t.Error("non-uint prev decoded")
		}
	}
}
