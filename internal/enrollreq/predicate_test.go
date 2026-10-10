package enrollreq

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// identityKeyAndSignature is the signature SPEC §3.1 exists to refuse
// (D-072 (c)): the identity point as a key, R the identity and S = 0. The
// equation [0]B = O + [k]O holds whatever k is, so Go's crypto/ed25519 accepts
// it over every message -- a key anyone can sign anything with. The identity
// is not of order L, so NORN-ED25519-v1 refuses it.
func identityKeyAndSignature(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, sig := make([]byte, 32), make([]byte, 64)
	key[0], sig[0] = 1, 1
	if !ed25519.Verify(key, []byte("any message"), sig) {
		t.Fatal("crypto/ed25519 no longer accepts the identity's signature, so this test shows nothing")
	}
	return key, sig
}

// A device_pk of the identity consents to nothing. Since 023r-c-iii the
// request is refused before its signature is read -- the identity is not a
// valid point (§3.1 item 2) -- so this no longer tells NORN-ED25519-v1 from
// crypto/ed25519 here; depgraph's guard holds the verifier at this site.
func TestARequestSignedByTheIdentityKeyDoesNotVerify(t *testing.T) {
	key, sig := identityKeyAndSignature(t)
	r := &Request{
		V: Version, TS: 1_760_000_000, Net: bytes.Repeat([]byte{7}, NetLen),
		DeviceID: "pi-cam", DevicePK: key, WGPK: bytes.Repeat([]byte{9}, 32), Sig: sig,
	}
	if Verify(r) {
		t.Error("a request signed by the identity key verified")
	}
	if err := Check(r, r.Net); err == nil {
		t.Error("Check accepted a request signed by the identity key")
	}
}
