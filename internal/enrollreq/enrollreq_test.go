package enrollreq

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func aRequest(t *testing.T) (*Request, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := keypair(t)
	wg := make([]byte, 32)
	if _, err := rand.Read(wg); err != nil {
		t.Fatal(err)
	}
	r := &Request{
		V: Version, TS: 1_760_000_000, Net: bytes.Repeat([]byte{7}, NetLen),
		DeviceID: "pi-cam", DevicePK: pub, WGPK: wg,
	}
	if err := Sign(r, priv); err != nil {
		t.Fatal(err)
	}
	return r, priv
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	r, _ := aRequest(t)
	if !Verify(r) {
		t.Fatal("a freshly signed request does not verify")
	}
	if err := Check(r, r.Net); err != nil {
		t.Fatal(err)
	}
}

func TestSignRefusesAKeyThatIsNotTheDeviceKey(t *testing.T) {
	r, _ := aRequest(t)
	_, other := keypair(t)
	if err := Sign(r, other); err == nil {
		t.Error("signed with a key that is not the request's device_pk")
	}
}

// The whole point of the domain prefix (§16.1): a device's signature over a
// request must be useless as a signature over an entry, and the other way
// round. Without the prefix these two preimages could coincide.
func TestARequestSignatureIsNotAnEntrySignature(t *testing.T) {
	r, _ := aRequest(t)
	env := &entry.Envelope{
		V: entry.Version, T: "enroll", Net: r.Net, TS: r.TS,
		Body: map[string]any{
			"device_id": r.DeviceID, "device_pk": r.DevicePK, "wg_pk": r.WGPK,
		},
	}
	ok, err := entry.Verify(env, entry.Signature{
		Kid: entry.Kid(r.DevicePK), Role: "device", Sig: r.Sig,
	}, r.DevicePK)
	if err == nil && ok {
		t.Fatal("a request signature verified as an entry signature")
	}
}

func TestAFlippedFieldBreaksTheSignature(t *testing.T) {
	r, _ := aRequest(t)
	r.WGPK = bytes.Repeat([]byte{9}, 32)
	if Verify(r) {
		t.Error("the signature survived a changed wg_pk")
	}
}

func TestCheckPinsTheNetwork(t *testing.T) {
	r, _ := aRequest(t)
	if err := Check(r, bytes.Repeat([]byte{0}, NetLen)); err == nil {
		t.Error("accepted a request for another network")
	}
}

// Absent and zero are different requests; a struct without a pointer would
// encode one as the other and change what the signature covers.
func TestAbsentExpiresIsNotZero(t *testing.T) {
	r, priv := aRequest(t)
	withoutExpires, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}

	zero := uint64(0)
	r.Expires = &zero
	if err := Sign(r, priv); err == nil {
		// expires must be after ts, so zero is invalid anyway -- but the
		// encoding must differ even before that rule applies.
		t.Fatal("signed a request whose expires precedes its ts")
	}

	future := r.TS + 60
	r.Expires = &future
	if err := Sign(r, priv); err != nil {
		t.Fatal(err)
	}
	withExpires, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(withoutExpires, withExpires) {
		t.Error("an absent expires encoded the same as a present one")
	}
}

func TestTextFormIsLowercaseAndPrefixed(t *testing.T) {
	r, _ := aRequest(t)
	text, err := Text(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text, HRP+"1") {
		t.Errorf("text = %q, want the %q prefix", text[:8], HRP+"1")
	}
	if text != strings.ToLower(text) {
		t.Error("the canonical text form is lowercase (SPEC §16.2)")
	}
}

func TestDecodeDoesNotVerify(t *testing.T) {
	// Decode is structure only, on purpose: Check is where belief happens.
	r, _ := aRequest(t)
	r.Sig = bytes.Repeat([]byte{4}, ed25519.SignatureSize)
	raw, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(raw); err != nil {
		t.Fatalf("Decode rejected a structurally valid request: %v", err)
	}
	back, _ := Decode(raw)
	if Verify(back) {
		t.Fatal("a forged signature verified")
	}
	if err := Check(back, nil); err == nil {
		t.Fatal("Check accepted a forged signature")
	}
}

func TestNewValidatesUpFront(t *testing.T) {
	pub, _ := keypair(t)
	net := bytes.Repeat([]byte{7}, NetLen)
	wg := bytes.Repeat([]byte{8}, 32)

	if _, err := New(net, "pi-cam", pub, wg, 1, nil, nil); err != nil {
		t.Fatalf("a good request was refused: %v", err)
	}
	// An empty label map and an absent one must encode identically: a caller
	// passing an empty map should not sign a different object.
	withEmpty, err := New(net, "pi-cam", pub, wg, 1, map[string]string{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	withNil, err := New(net, "pi-cam", pub, wg, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Preimage(withEmpty)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Preimage(withNil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("an empty label map changed the signed bytes")
	}

	past := uint64(0)
	for _, bad := range []struct {
		why string
		run func() (*Request, error)
	}{
		{"uppercase device_id", func() (*Request, error) { return New(net, "Pi-Cam", pub, wg, 1, nil, nil) }},
		{"short net", func() (*Request, error) { return New(net[:8], "pi-cam", pub, wg, 1, nil, nil) }},
		{"expires before ts", func() (*Request, error) { return New(net, "pi-cam", pub, wg, 1, nil, &past) }},
	} {
		if _, err := bad.run(); err == nil {
			t.Errorf("New accepted a request with a %s", bad.why)
		}
	}
}
