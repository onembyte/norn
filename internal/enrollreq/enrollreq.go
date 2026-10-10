// Package enrollreq implements enrollment requests (SPEC §16): what a device
// hands a signer.
//
// A request is the only Norn format a *device* produces, and the only one that
// crosses an untrusted channel -- a phone camera -- before anybody has decided
// to trust it. Two consequences shape this package:
//
//   - nothing here consults any state, because a request is not a log entry and
//     never becomes one. A signer reads a request and writes an `enroll` entry.
//   - Decode validates structure and nothing more. Believing a request means
//     calling Check, which verifies the signature. The split is deliberate: it
//     makes "I displayed an unverified request" a visible mistake in the caller.
package enrollreq

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/onembyte/norn/internal/bech32m"
	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/ed25519v1"
	"github.com/onembyte/norn/internal/fields"
)

const (
	// Version is the only `v` this package accepts.
	Version = uint64(1)
	// Domain names the format; PreimagePrefix separates its signatures from
	// §4.2's, so a device signature over a request can never be replayed as a
	// signature over an entry.
	Domain         = "norn/enroll-request/v1"
	PreimagePrefix = Domain + "\n"
	// HRP is the bech32m human-readable part of the text form (§16.2).
	HRP = "norn"
	// NetLen is the length of a net_id (§2).
	NetLen = 16
)

// Request is a decoded enrollment request.
//
// Expires is a pointer because absent and zero are different requests that
// would otherwise encode differently under the same struct -- the same reason
// entry.Envelope carries `after` as a pointer.
type Request struct {
	V        uint64
	TS       uint64
	Net      []byte
	DeviceID string
	DevicePK []byte
	WGPK     []byte
	Labels   map[string]string
	Expires  *uint64
	Sig      []byte
}

// ErrUnsigned reports a request that carries no signature yet.
var ErrUnsigned = errors.New("enrollreq: the request is not signed")

func errorf(format string, args ...any) error {
	return fmt.Errorf("enrollreq: "+format, args...)
}

func (r *Request) toMap(withSig bool) (map[string]any, error) {
	if err := r.validate(withSig); err != nil {
		return nil, err
	}
	m := map[string]any{
		"v": r.V, "ts": r.TS, "net": r.Net, "device_id": r.DeviceID,
		"device_pk": r.DevicePK, "wg_pk": r.WGPK,
	}
	if len(r.Labels) > 0 {
		labels := make(map[string]any, len(r.Labels))
		for k, v := range r.Labels {
			labels[k] = v
		}
		m["labels"] = labels
	}
	if r.Expires != nil {
		m["expires"] = *r.Expires
	}
	if withSig {
		m["sig"] = r.Sig
	}
	return m, nil
}

// New builds an unsigned request, checking the field rules now rather than at
// signing time, so a caller learns about a bad device_id before it asks a
// hardware token to touch-confirm anything.
func New(net []byte, deviceID string, devicePK, wgPK []byte, ts uint64,
	labels map[string]string, expires *uint64) (*Request, error) {
	r := &Request{
		V: Version, TS: ts, Net: net, DeviceID: deviceID,
		DevicePK: devicePK, WGPK: wgPK, Labels: labels, Expires: expires,
	}
	if len(r.Labels) == 0 {
		r.Labels = nil
	}
	if err := r.validate(false); err != nil {
		return nil, err
	}
	return r, nil
}

// Encode returns the deterministic CBOR form, signature included.
func Encode(r *Request) ([]byte, error) {
	m, err := r.toMap(true)
	if err != nil {
		return nil, err
	}
	return cbor.Encode(m)
}

// Preimage returns the bytes every signature covers.
func Preimage(r *Request) ([]byte, error) {
	m, err := r.toMap(false)
	if err != nil {
		return nil, err
	}
	body, err := cbor.Encode(m)
	if err != nil {
		return nil, err
	}
	return append([]byte(PreimagePrefix), body...), nil
}

// Text returns the bech32m form a device prints as text and as a QR (§16.2).
func Text(r *Request) (string, error) {
	raw, err := Encode(r)
	if err != nil {
		return "", err
	}
	return bech32m.Encode(HRP, raw)
}

// Sign signs with the device key, which must be the request's own DevicePK.
func Sign(r *Request, key ed25519.PrivateKey) error {
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return errorf("not an Ed25519 key")
	}
	if len(r.DevicePK) != ed25519.PublicKeySize || string(public) != string(r.DevicePK) {
		return errorf("the signing key is not the request's device_pk")
	}
	preimage, err := Preimage(r)
	if err != nil {
		return err
	}
	r.Sig = ed25519.Sign(key, preimage)
	return nil
}

// Decode parses and validates structure. It does not verify the signature.
func Decode(raw []byte) (*Request, error) {
	if len(raw) > cbor.MaxEntryBytes {
		return nil, errorf("request is larger than MaxEntryBytes")
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		return nil, errorf("not deterministic CBOR: %w", err)
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, errorf("a request is a CBOR map")
	}
	return fromMap(m)
}

// DecodeText parses the bech32m form, rejecting any other prefix.
func DecodeText(text string) (*Request, error) {
	hrp, raw, err := bech32m.Decode(text)
	if err != nil {
		return nil, errorf("not a bech32m request: %w", err)
	}
	if hrp != HRP {
		return nil, errorf("wrong human-readable part: %q, want %q", hrp, HRP)
	}
	return Decode(raw)
}

// Verify reports whether Sig is a valid signature by DevicePK.
func Verify(r *Request) bool {
	if len(r.DevicePK) != ed25519.PublicKeySize || len(r.Sig) != ed25519.SignatureSize {
		return false
	}
	preimage, err := Preimage(r)
	if err != nil {
		return false
	}
	return ed25519v1.Verify(r.DevicePK, preimage, r.Sig)
}

// Check validates, pins the network when net is non-nil, and verifies the
// signature.
//
// This is what a signer calls before showing anything to a human: a request
// displayed before its signature is checked is a request whose text an
// attacker chose.
func Check(r *Request, net []byte) error {
	if err := r.validate(true); err != nil {
		return err
	}
	if net != nil && string(net) != string(r.Net) {
		return errorf("request is for another network")
	}
	if !Verify(r) {
		return errorf("signature does not verify under device_pk")
	}
	return nil
}

var (
	required = []string{"v", "ts", "net", "sig", "wg_pk", "device_id", "device_pk"}
	optional = []string{"labels", "expires"}
)

func fromMap(m map[string]any) (*Request, error) {
	known := map[string]bool{}
	for _, k := range append(append([]string{}, required...), optional...) {
		known[k] = true
	}
	for k := range m {
		if !known[k] {
			return nil, errorf("unknown key: %q", k)
		}
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return nil, errorf("missing: %q", k)
		}
	}

	r := &Request{}
	var err error
	if r.V, err = fields.Uint(m["v"], "v"); err != nil {
		return nil, errorf("%w", err)
	}
	if r.TS, err = fields.Uint(m["ts"], "ts"); err != nil {
		return nil, errorf("%w", err)
	}
	if r.Net, err = fields.Bytes(m["net"], NetLen, "net"); err != nil {
		return nil, errorf("%w", err)
	}
	if r.DeviceID, err = fields.DeviceID(m["device_id"]); err != nil {
		return nil, errorf("%w", err)
	}
	if r.DevicePK, err = fields.PublicKey(m["device_pk"], "device_pk"); err != nil {
		return nil, errorf("%w", err)
	}
	if r.WGPK, err = fields.PublicKey(m["wg_pk"], "wg_pk"); err != nil {
		return nil, errorf("%w", err)
	}
	if r.Sig, err = fields.Signature(m["sig"]); err != nil {
		return nil, errorf("%w", err)
	}
	if r.Labels, err = fields.Labels(m["labels"]); err != nil {
		return nil, errorf("%w", err)
	}
	if raw, present := m["expires"]; present {
		expires, err := fields.Uint(raw, "expires")
		if err != nil {
			return nil, errorf("%w", err)
		}
		r.Expires = &expires
	}
	if err := r.validate(true); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Request) validate(withSig bool) error {
	if r.V != Version {
		return errorf("unsupported version: %d", r.V)
	}
	if len(r.Net) != NetLen {
		return errorf("net must be %d bytes", NetLen)
	}
	if _, err := fields.DeviceID(r.DeviceID); err != nil {
		return errorf("%w", err)
	}
	if len(r.DevicePK) != fields.KeyLen || len(r.WGPK) != fields.KeyLen {
		return errorf("device_pk and wg_pk must be %d bytes", fields.KeyLen)
	}
	if len(r.Labels) > fields.MaxLabels {
		return errorf("labels must be a map of at most %d entries", fields.MaxLabels)
	}
	for k, v := range r.Labels {
		if len(v) > fields.MaxLabelValue {
			return errorf("label %q is longer than %d bytes", k, fields.MaxLabelValue)
		}
	}
	if r.Expires != nil && *r.Expires <= r.TS {
		return errorf("expires must be after ts")
	}
	if withSig {
		if len(r.Sig) == 0 {
			return ErrUnsigned
		}
		if len(r.Sig) != ed25519.SignatureSize {
			return errorf("sig must be %d bytes", ed25519.SignatureSize)
		}
	}
	return nil
}
