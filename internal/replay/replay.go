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
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/onembyte/norn/internal/ed25519v1"
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
	return ed25519v1.Verify(public, message, signature)
}

// Replay applies entries under an anchor. It never returns an error: an entry
// that does not take effect is recorded in state.Rejected.
func Replay(anchor Anchor, entries [][]byte) *state.State {
	return New(anchor).Apply(entries...)
}

func replayWith(anchor Anchor, entries [][]byte, verify verifier) *state.State {
	return newWith(anchor, verify).Apply(entries...)
}

// Replayer is the fold of §5 as a value that can be resumed (H4-a).
//
// Replay is that fold run from entry 0 to the end, and a node that re-ran it
// on every grown head did work proportional to the whole history on every
// cycle. What the fold has to carry between entries is the state and the
// seen set of §5.1 step 1: a `dup-entry` copy is refused because its original
// is remembered, and a fold resumed without that memory would apply the copy
// -- the SEC-001 attack by another door. So the two travel together, and
// applying a prefix and then the rest is the same as applying the whole,
// byte for byte, at every split (resume_test.go).
type Replayer struct {
	r  *replayer
	st *state.State
	// aborted is set by a bad genesis. Nothing after it is this network's
	// (§5.1), so the fold applies nothing further however much it is given.
	aborted bool
}

// New starts a fold under an anchor.
func New(anchor Anchor) *Replayer { return newWith(anchor, realVerify) }

func newWith(anchor Anchor, verify verifier) *Replayer {
	return &Replayer{
		r:  &replayer{anchor: anchor, verify: verify, seen: map[string]bool{}},
		st: state.New(anchor.Net),
	}
}

// Apply folds more entries in, in log order, and returns the state so far.
// The returned state is the fold's own: a caller that keeps it sees it move.
func (p *Replayer) Apply(entries ...[]byte) *state.State {
	for _, raw := range entries {
		if p.aborted {
			return p.st
		}
		index := p.st.Size
		if index == 0 {
			if err := p.r.applyGenesis(p.st, raw); err != nil {
				p.st = state.New(p.r.anchor.Net)
				p.st.Rejected = append(p.st.Rejected, state.Rejection{Index: 0, Reason: ReasonBadGenesis})
				p.aborted = true
				return p.st
			}
			p.st.Size = 1
			continue
		}
		if err := p.r.apply(p.st, raw, index); err != nil {
			code, ok := reasonOf(err)
			if !ok {
				code = ReasonDecode
			}
			p.st.Rejected = append(p.st.Rejected, state.Rejection{Index: index, Reason: code})
		}
		p.st.Size = index + 1
	}
	return p.st
}

// Clone is a copy of the fold that can be resumed without moving this one:
// the state, the seen set and the abort travel together, as they must.
func (p *Replayer) Clone() *Replayer {
	seen := make(map[string]bool, len(p.r.seen))
	for k := range p.r.seen {
		seen[k] = true
	}
	return &Replayer{
		r:       &replayer{anchor: p.r.anchor, verify: p.r.verify, seen: seen},
		st:      p.st.Clone(),
		aborted: p.aborted,
	}
}

// State is the state so far.
func (p *Replayer) State() *state.State { return p.st }

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

// fieldKey reads an Ed25519 key a governance entry admits: 32 bytes and a
// valid point (§3.1 item 2), else `decode`.
func fieldKey(body map[string]any, key string) ([]byte, error) {
	public, err := fieldBytes(body, key, entry.KeyLen)
	if err != nil {
		return nil, err
	}
	if !ed25519v1.ValidPoint(public) {
		return nil, rejectWith(ReasonDecode)
	}
	return public, nil
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
