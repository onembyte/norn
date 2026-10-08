// Package replay turns a log into state: the pure function of SPEC.md §5.
//
// Every rule that decides whether an entry takes effect lives here, one handler
// per type, so the reason codes of §5.2 map one to one onto rejections. The
// numbered procedure of §5.1 is followed literally, including the ordering that
// makes an under-signed governance entry with a malformed body `threshold`
// rather than `decode` (D-046).
package replay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/state"
)

// Anchor is what a verifier is provisioned with out of band (§5, §9).
type Anchor struct {
	Net         []byte
	GenesisHash []byte
}

// Reason codes, the closed list of §5.2.
const (
	ReasonDecode        = "decode"
	ReasonUnknownType   = "unknown-type"
	ReasonBadGenesis    = "bad-genesis"
	ReasonDupGenesis    = "dup-genesis"
	ReasonDupEntry      = "dup-entry"
	ReasonAfter         = "after"
	ReasonThreshold     = "threshold"
	ReasonNoDeviceSig   = "no-device-sig"
	ReasonDupID         = "dup-id"
	ReasonDupWg         = "dup-wg"
	ReasonUnknownDevice = "unknown-device"
	ReasonNotActive     = "not-active"
	ReasonDupKey        = "dup-key"
	ReasonUnknownKey    = "unknown-key"
	ReasonRootInvariant = "root-invariant"
	ReasonBadThr        = "bad-thr"
)

// reject carries a reason code out of a handler.
type reject struct{ code string }

func (r reject) Error() string { return r.code }

func rejectWith(code string) error { return reject{code} }

func reasonOf(err error) (string, bool) {
	var r reject
	if errors.As(err, &r) {
		return r.code, true
	}
	return "", false
}

// verifier is the signature check, injectable so a test can prove that
// stubbing it changes the outcome (D-043).
type verifier func(public, message, signature []byte) bool

func realVerify(public, message, signature []byte) bool {
	return ed25519.Verify(public, message, signature)
}

// Replay applies entries under an anchor. It never returns an error: an entry
// that does not take effect is recorded in state.Rejected.
func Replay(anchor Anchor, entries [][]byte) *state.State {
	return replayWith(anchor, entries, realVerify)
}

func replayWith(anchor Anchor, entries [][]byte, verify verifier) *state.State {
	st := state.New(anchor.Net)
	if len(entries) == 0 {
		return st
	}

	r := &replayer{anchor: anchor, verify: verify, seen: map[string]bool{}}
	if err := r.applyGenesis(st, entries[0]); err != nil {
		st = state.New(anchor.Net)
		st.Rejected = append(st.Rejected, state.Rejection{Index: 0, Reason: ReasonBadGenesis})
		return st
	}
	st.Size = 1

	for i, raw := range entries[1:] {
		index := uint64(i + 1)
		if err := r.apply(st, raw, index); err != nil {
			code, ok := reasonOf(err)
			if !ok {
				code = ReasonDecode
			}
			st.Rejected = append(st.Rejected, state.Rejection{Index: index, Reason: code})
		}
		st.Size = index + 1
	}
	return st
}

type replayer struct {
	anchor Anchor
	verify verifier
	seen   map[string]bool
}

// remember records an entry's duplicate key (§5.1 step 1) and reports whether
// it was new. The key is the content hash when the entry decodes and its
// envelope passes §4.1, `net` included: the same signed content under any other
// signature list is then the same entry, so a copy of a past entry with one
// unresolvable signature added, a surplus one dropped or a role relabelled is
// `dup-entry` rather than a second application (D-070, audit SEC-001). For an
// entry that does not decode the key is its bytes, so a copy of it is still
// `dup-entry` and not a second `decode`.
func (r *replayer) remember(raw []byte) bool {
	key := string(entry.EntryHash(raw))
	if env, err := entry.Decode(raw); err == nil && bytes.Equal(env.Net, r.anchor.Net) {
		if pre, err := entry.Preimage(env); err == nil {
			sum := sha256.Sum256(pre)
			key = string(sum[:])
		}
	}
	if r.seen[key] {
		return false
	}
	r.seen[key] = true
	return true
}

// apply runs the numbered procedure of §5.1 for one entry after genesis.
func (r *replayer) apply(st *state.State, raw []byte, index uint64) error {
	// 1. Duplicate check, before validation: an exact entry is usable at most
	// once, accepted or not, so a rejected one cannot be re-inserted later
	// against a changed state (D-031).
	if !r.remember(raw) {
		return rejectWith(ReasonDupEntry)
	}
	// 2-3. Decode and envelope schema.
	env, err := entry.Decode(raw)
	if err != nil {
		return rejectWith(ReasonDecode)
	}
	if !bytes.Equal(env.Net, r.anchor.Net) {
		return rejectWith(ReasonDecode)
	}
	// 4. Unknown type, 5. a second genesis.
	if !entry.Types[env.T] {
		return rejectWith(ReasonUnknownType)
	}
	if env.T == "genesis" {
		return rejectWith(ReasonDupGenesis)
	}
	// 6. Ordering guard.
	if env.After != nil && *env.After > index {
		return rejectWith(ReasonAfter)
	}
	// 7. Authorisation -- BEFORE the body check, so an under-signed governance
	// entry with a malformed body is `threshold` and never reaches step 8.
	if governance[env.T] {
		if r.countRole(st, env, "root") < st.RootThr {
			return rejectWith(ReasonThreshold)
		}
	} else if env.T == "note" {
		if r.countRole(st, env, "signer") == 0 && r.countRole(st, env, "root") == 0 {
			return rejectWith(ReasonThreshold)
		}
	}
	// 8. The type rule, beginning with its body schema.
	if err := checkBody(env.T, env.Body); err != nil {
		return err
	}
	return handlers[env.T](r, st, env, index)
}

// countRole returns how many distinct keys of a role produced a valid
// signature. A signature whose kid does not resolve in the declared role is
// silently not counted; an invalid one likewise (§5.2).
func (r *replayer) countRole(st *state.State, env *entry.Envelope, role string) uint64 {
	var keys map[string]string
	switch role {
	case "root":
		keys = st.Roots
	case "signer":
		keys = st.Signers
	default:
		return 0
	}
	seen := map[string]bool{}
	for _, sig := range env.Sigs {
		if sig.Role != role || seen[sig.Kid] {
			continue
		}
		encoded, ok := keys[sig.Kid]
		if !ok {
			continue
		}
		public, err := hex.DecodeString(encoded)
		if err != nil {
			continue
		}
		if r.signatureValid(env, sig, public) {
			seen[sig.Kid] = true
		}
	}
	return uint64(len(seen))
}

// deviceSigned reports whether the entry carries a valid `device` signature by
// exactly this key.
func (r *replayer) deviceSigned(env *entry.Envelope, public []byte) bool {
	kid := entry.Kid(public)
	for _, sig := range env.Sigs {
		if sig.Role == "device" && sig.Kid == kid && r.signatureValid(env, sig, public) {
			return true
		}
	}
	return false
}

func (r *replayer) signatureValid(env *entry.Envelope, sig entry.Signature, public []byte) bool {
	pre, err := entry.Preimage(env)
	if err != nil {
		return false
	}
	return r.verify(public, pre, sig.Sig)
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func fieldBytes(body map[string]any, key string, n int) ([]byte, error) {
	raw, ok := body[key].([]byte)
	if !ok || len(raw) != n {
		return nil, rejectWith(ReasonDecode)
	}
	return raw, nil
}

func fieldUint(body map[string]any, key string) (uint64, error) {
	v, ok := body[key].(uint64)
	if !ok {
		return 0, rejectWith(ReasonDecode)
	}
	return v, nil
}

func fieldText(body map[string]any, key string, maxBytes int) (string, error) {
	v, ok := body[key].(string)
	if !ok || len(v) > maxBytes {
		return "", rejectWith(ReasonDecode)
	}
	return v, nil
}
