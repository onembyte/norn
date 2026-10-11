package replay

import (
	"bytes"
	"encoding/hex"

	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/fields"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/state"
)

// governance names the types that need a root quorum before their rule runs.
var governance = map[string]bool{
	"signer_add": true, "signer_remove": true, "signer_thr": true,
	"root_add": true, "root_remove": true, "root_thr": true,
	"log_key": true, "policy": true, "params": true,
}

// bodySchema is the closed key set per type (§4.3): required, then optional.
var bodySchema = map[string]struct{ required, optional []string }{
	"genesis": {[]string{"name", "roots", "root_thr", "signers", "signer_thr"}, []string{"params"}},
	// The device's consent, verbatim (SPEC §4.3): one field, so a signer
	// cannot restate a claim the device did not make.
	"enroll":        {[]string{"request"}, nil},
	"rotate":        {[]string{"device_id", "wg_pk"}, []string{"device_pk"}},
	"revoke":        {[]string{"device_id"}, []string{"reason"}},
	"signer_add":    {[]string{"pk"}, nil},
	"signer_remove": {[]string{"kid"}, nil},
	"signer_thr":    {[]string{"thr"}, nil},
	"root_add":      {[]string{"pk"}, nil},
	"root_remove":   {[]string{"kid"}, nil},
	"root_thr":      {[]string{"thr"}, nil},
	"log_key":       {[]string{"pk", "overlap"}, nil},
	"policy":        {[]string{"text"}, nil},
	"note":          {[]string{"text"}, nil},
	// params is the exception: its keys are the §4.5 parameter names.
	"params": {nil, []string{"checkpoint_interval", "staleness", "mmd", "rotate_needs_signer", "routes"}},
}

func checkBody(entryType string, body map[string]any) error {
	schema, ok := bodySchema[entryType]
	if !ok {
		return rejectWith(ReasonUnknownType)
	}
	allowed := map[string]bool{}
	for _, k := range schema.required {
		allowed[k] = true
		if _, present := body[k]; !present {
			return rejectWith(ReasonDecode)
		}
	}
	for _, k := range schema.optional {
		allowed[k] = true
	}
	for k := range body {
		if !allowed[k] {
			return rejectWith(ReasonDecode)
		}
	}
	return nil
}

type handler func(*replayer, *state.State, *entry.Envelope, uint64) error

var handlers map[string]handler

func init() {
	handlers = map[string]handler{
		"enroll": hEnroll, "rotate": hRotate, "revoke": hRevoke,
		"signer_add": hSignerAdd, "signer_remove": hSignerRemove, "signer_thr": hSignerThr,
		"root_add": hRootAdd, "root_remove": hRootRemove, "root_thr": hRootThr,
		"log_key": hLogKey, "policy": hPolicy, "params": hParams, "note": hNote,
	}
}

const (
	maxText   = 4096
	maxReason = 256
	maxName   = 64
)

func deviceID(body map[string]any) (string, error) {
	id, err := fields.DeviceID(body["device_id"])
	if err != nil {
		return "", rejectWith(ReasonDecode)
	}
	return id, nil
}

// hEnroll applies SPEC §5.1 `enroll`: the device's consent is the embedded
// request (§4.3), not a signature on this envelope.
//
// The envelope is built by a signer, who chooses `ts` and `after`; the device
// is headless and one-way and never sees it. So `no-device-sig` here means the
// request's *own* signature does not verify -- and because the request is
// embedded verbatim, a signer cannot restate a claim the device did not make.
func hEnroll(r *replayer, st *state.State, env *entry.Envelope, index uint64) error {
	raw, ok := env.Body["request"].([]byte)
	if !ok {
		return rejectWith(ReasonDecode)
	}
	request, err := enrollreq.Decode(raw)
	if err != nil {
		return rejectWith(ReasonDecode)
	}
	if !bytes.Equal(request.Net, env.Net) {
		return rejectWith(ReasonDecode)
	}
	if !enrollreq.Verify(request) {
		return rejectWith(ReasonNoDeviceSig)
	}

	if r.countRole(st, env, "signer") < st.SignerThr {
		return rejectWith(ReasonThreshold)
	}
	if d, ok := st.Devices[request.DeviceID]; ok && d.Status == state.StatusActive {
		return rejectWith(ReasonDupID)
	}
	if _, taken := st.ActiveWg[hexOf(request.WGPK)]; taken {
		return rejectWith(ReasonDupWg)
	}

	labels := request.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	var expires uint64
	if request.Expires != nil {
		expires = *request.Expires
	}
	st.Devices[request.DeviceID] = state.Device{
		DevicePk: hexOf(request.DevicePK), WgPk: hexOf(request.WGPK),
		Status: state.StatusActive, SinceIndex: index, Labels: labels, Expires: expires,
	}
	st.ActiveWg[hexOf(request.WGPK)] = request.DeviceID
	return nil
}

func hRotate(r *replayer, st *state.State, env *entry.Envelope, index uint64) error {
	id, err := deviceID(env.Body)
	if err != nil {
		return err
	}
	wgPk, err := fieldBytes(env.Body, "wg_pk", entry.KeyLen)
	if err != nil {
		return err
	}
	// D-075 admits the incoming key in the body step, before device lookup.
	var incoming []byte
	if _, present := env.Body["device_pk"]; present {
		if incoming, err = fieldKey(env.Body, "device_pk"); err != nil {
			return err
		}
	}
	device, known := st.Devices[id]
	if !known {
		return rejectWith(ReasonUnknownDevice)
	}
	if device.Status != state.StatusActive {
		return rejectWith(ReasonNotActive)
	}
	current, err := hex.DecodeString(device.DevicePk)
	if err != nil {
		return rejectWith(ReasonDecode)
	}
	if !r.deviceSigned(env, current) {
		return rejectWith(ReasonNoDeviceSig)
	}
	if needsSigner, _ := st.Params["rotate_needs_signer"].(bool); needsSigner {
		if r.countRole(st, env, "signer") < st.SignerThr {
			return rejectWith(ReasonThreshold)
		}
	}
	if owner, taken := st.ActiveWg[hexOf(wgPk)]; taken && owner != id {
		return rejectWith(ReasonDupWg)
	}
	if incoming != nil {
		// Proof of possession of the key being installed (D-032).
		if !r.deviceSigned(env, incoming) {
			return rejectWith(ReasonNoDeviceSig)
		}
	}
	delete(st.ActiveWg, device.WgPk)
	device.WgPk = hexOf(wgPk)
	if incoming != nil {
		device.DevicePk = hexOf(incoming)
	}
	st.Devices[id] = device
	st.ActiveWg[device.WgPk] = id
	return nil
}

func hRevoke(r *replayer, st *state.State, env *entry.Envelope, index uint64) error {
	id, err := deviceID(env.Body)
	if err != nil {
		return err
	}
	if _, present := env.Body["reason"]; present {
		if _, err := fieldText(env.Body, "reason", maxReason); err != nil {
			return err
		}
	}
	device, known := st.Devices[id]
	if !known {
		return rejectWith(ReasonUnknownDevice)
	}
	if device.Status != state.StatusActive {
		return rejectWith(ReasonNotActive)
	}
	current, err := hex.DecodeString(device.DevicePk)
	if err != nil {
		return rejectWith(ReasonDecode)
	}
	authorised := r.countRole(st, env, "signer") >= st.SignerThr ||
		r.countRole(st, env, "root") >= st.RootThr ||
		r.deviceSigned(env, current)
	if !authorised {
		return rejectWith(ReasonThreshold)
	}
	device.Status = state.StatusRevoked
	device.SinceIndex = index
	st.Devices[id] = device
	delete(st.ActiveWg, device.WgPk)
	return nil
}

func addKey(st *state.State, into map[string]string, body map[string]any) error {
	pk, err := fieldKey(body, "pk")
	if err != nil {
		return err
	}
	kid := entry.Kid(pk)
	if _, ok := st.Roots[kid]; ok {
		return rejectWith(ReasonDupKey)
	}
	if _, ok := st.Signers[kid]; ok {
		return rejectWith(ReasonDupKey)
	}
	into[kid] = hexOf(pk)
	return nil
}

func hSignerAdd(_ *replayer, st *state.State, env *entry.Envelope, _ uint64) error {
	return addKey(st, st.Signers, env.Body)
}

func hRootAdd(_ *replayer, st *state.State, env *entry.Envelope, _ uint64) error {
	return addKey(st, st.Roots, env.Body)
}

func kidField(body map[string]any) (string, error) {
	kid, ok := body["kid"].(string)
	if !ok || len(kid) != 16 {
		return "", rejectWith(ReasonDecode)
	}
	for _, c := range kid {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", rejectWith(ReasonDecode)
		}
	}
	return kid, nil
}

func hSignerRemove(_ *replayer, st *state.State, env *entry.Envelope, _ uint64) error {
	kid, err := kidField(env.Body)
	if err != nil {
		return err
	}
	if _, ok := st.Signers[kid]; !ok {
		return rejectWith(ReasonUnknownKey)
	}
	// No quorum invariant: removing a compromised signer key must always be
	// possible, including the last one (D-028).
	delete(st.Signers, kid)
	return nil
}

func hRootRemove(_ *replayer, st *state.State, env *entry.Envelope, _ uint64) error {
	kid, err := kidField(env.Body)
	if err != nil {
		return err
	}
	if _, ok := st.Roots[kid]; !ok {
		return rejectWith(ReasonUnknownKey)
	}
	remaining := uint64(len(st.Roots) - 1)
	if remaining < st.RootThr || remaining < 1 {
		return rejectWith(ReasonRootInvariant)
	}
	delete(st.Roots, kid)
	return nil
}

func threshold(body map[string]any, size int) (uint64, error) {
	thr, err := fieldUint(body, "thr")
	if err != nil {
		return 0, err
	}
	// A well-formed uint out of range is `bad-thr`, never `decode` (D-039).
	if thr < 1 || thr > uint64(size) {
		return 0, rejectWith(ReasonBadThr)
	}
	return thr, nil
}

func hSignerThr(_ *replayer, st *state.State, env *entry.Envelope, _ uint64) error {
	thr, err := threshold(env.Body, len(st.Signers))
	if err != nil {
		return err
	}
	st.SignerThr = thr
	return nil
}

func hRootThr(_ *replayer, st *state.State, env *entry.Envelope, _ uint64) error {
	thr, err := threshold(env.Body, len(st.Roots))
	if err != nil {
		return err
	}
	st.RootThr = thr
	return nil
}

func hLogKey(_ *replayer, st *state.State, env *entry.Envelope, index uint64) error {
	pk, err := fieldKey(env.Body, "pk")
	if err != nil {
		return err
	}
	overlap, err := fieldUint(env.Body, "overlap")
	if err != nil {
		return err
	}
	// Appends, never replaces (§5.3): SinceIndex is this entry's own index.
	st.LogKeys = append(st.LogKeys, state.LogKey{
		Overlap: overlap, Pk: hexOf(pk), SinceIndex: index})
	return nil
}

func hPolicy(_ *replayer, st *state.State, env *entry.Envelope, _ uint64) error {
	text, err := fieldText(env.Body, "text", maxText)
	if err != nil {
		return err
	}
	// A `policy` entry whose text is not a policy is malformed, whatever an
	// in-log policy turns out to govern. Without this the fixture published
	// the canonical-JSON torture string as the network's policy for six
	// phases, and §4.5 read literally made this network unverifiable.
	if _, err := policy.Parse(text); err != nil {
		return rejectWith(ReasonDecode)
	}
	st.Policy = text
	return nil
}

func hParams(_ *replayer, st *state.State, env *entry.Envelope, _ uint64) error {
	if len(env.Body) == 0 {
		return rejectWith(ReasonDecode)
	}
	// Every key is checked before any is applied. §5.1: a rejected entry
	// changes nothing -- and this handler wrote each key as it went, so an
	// entry with one good key and one bad one landed the good key and was
	// then rejected, in whatever order Go visited the map. Two nodes on one
	// log disagreed about `mmd`; one node disagreed with itself from poll to
	// poll (SEC-010).
	checked := make(map[string]any, len(env.Body))
	for key, value := range env.Body {
		typed, ok := checkParam(key, value)
		if !ok {
			return rejectWith(ReasonDecode)
		}
		checked[key] = typed
	}
	for key, value := range checked {
		st.Params[key] = value
	}
	return nil
}

// checkParam is §4.5's type rule for one parameter, shared by a `params`
// entry and a genesis so the two paths cannot disagree (cold gate run 8,
// D20). `rotate_needs_signer` is a bool; `routes` is text from a closed set
// (D-073); everything else is a uint.
func checkParam(key string, value any) (any, bool) {
	switch key {
	case "rotate_needs_signer":
		b, ok := value.(bool)
		return b, ok
	case "routes":
		s, ok := value.(string)
		return s, ok && (s == state.RoutesGranted || s == state.RoutesAdvisory)
	default:
		n, ok := value.(uint64)
		return n, ok
	}
}

func hNote(_ *replayer, _ *state.State, env *entry.Envelope, _ uint64) error {
	_, err := fieldText(env.Body, "text", maxText)
	return err
}
