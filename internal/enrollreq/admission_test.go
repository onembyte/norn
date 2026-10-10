package enrollreq

import (
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"

	"github.com/onembyte/norn/internal/cbor"
)

// notValidPoints: a point of order 8, and an honest key with it added -- the
// small-order and mixed-order keys SPEC §3.1 item 1 refuses.
func notValidPoints(t *testing.T, honest []byte) map[string][]byte {
	t.Helper()
	small, err := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := new(edwards25519.Point).SetBytes(small)
	if err != nil {
		t.Fatal(err)
	}
	a, err := new(edwards25519.Point).SetBytes(honest)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"small-order": small,
		"mixed-order": new(edwards25519.Point).Add(a, torsion).Bytes(),
	}
}

// §3.1 item 2, §16.1: a request's device_pk is admitted only as a valid point.
// A request naming one that is not does not decode -- `norn sign` will not
// countersign it, and replay's enroll row calls it `decode` -- and cannot be
// built.
// wg_pk is an X25519 key, not an Ed25519 one, and §3.1 says nothing about it:
// the same bytes there still decode.
func TestARequestsDevicePKMustBeAValidPoint(t *testing.T) {
	r, _ := aRequest(t)
	honest, err := r.toMap(true)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(field string, value []byte) []byte {
		t.Helper()
		m := map[string]any{}
		for k, v := range honest {
			m[k] = v
		}
		m[field] = value
		raw, err := cbor.Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := Decode(encode("device_pk", r.DevicePK)); err != nil {
		t.Fatalf("the honest request does not decode: %v; the test shows nothing", err)
	}
	for kind, bad := range notValidPoints(t, r.DevicePK) {
		if _, err := Decode(encode("device_pk", bad)); err == nil {
			t.Errorf("a request with a %s device_pk decoded", kind)
		}
		if _, err := New(r.Net, r.DeviceID, bad, r.WGPK, r.TS, nil, nil); err == nil {
			t.Errorf("New built a request with a %s device_pk", kind)
		}
		if _, err := Decode(encode("wg_pk", bad)); err != nil {
			t.Errorf("a request whose wg_pk has the %s key's bytes was refused: %v", kind, err)
		}
	}
}
