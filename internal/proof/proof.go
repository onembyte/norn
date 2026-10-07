// Package proof builds and checks the per-device proof bundles of SPEC.md §8.
//
// A bundle is self-contained on purpose: the checkpoint, the index, the entry
// and the inclusion proof travel together, so anyone holding norn.trust can
// check one without reaching the log it came from. That is what makes it
// useful in an alarm, an audit trail, or a bug report -- evidence that survives
// being copied out of the system that produced it.
package proof

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	upstream "golang.org/x/mod/sumdb/tlog"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
)

// Version is the bundle format version.
const Version = uint64(1)

// ErrProof reports a bundle that is malformed or does not check out.
var ErrProof = errors.New("proof bundle error")

func proofErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProof, fmt.Sprintf(format, args...))
}

// refuse is a bundle error carrying the §10.1 code of the step that refused
// (D-061). What is wrong with the reader's anchor goes through proofErrorf
// alone: §10.1's codes describe the bundle, not the configuration.
func refuse(code refusal.Code, format string, args ...any) error {
	return refusal.Wrap(code, proofErrorf(format, args...))
}

// Bundle is one device's evidence (§8.1).
type Bundle struct {
	Device     string
	Index      int64
	Entry      []byte
	Proof      []upstream.Hash
	Checkpoint string // the signed checkpoint note, verbatim
}

// Build assembles a bundle.
func Build(device string, index int64, raw []byte, proof upstream.RecordProof, checkpoint string) (*Bundle, error) {
	if device == "" {
		return nil, proofErrorf("a bundle needs a device id")
	}
	return &Bundle{Device: device, Index: index, Entry: raw,
		Proof: append([]upstream.Hash(nil), proof...), Checkpoint: checkpoint}, nil
}

// Encode renders the bundle as deterministic CBOR (§4.0).
func (b *Bundle) Encode() ([]byte, error) {
	hashes := make([]any, 0, len(b.Proof))
	for _, h := range b.Proof {
		hashes = append(hashes, append([]byte(nil), h[:]...))
	}
	return cbor.Encode(map[string]any{
		"v": Version, "device": b.Device, "index": uint64(b.Index),
		"entry": b.Entry, "proof": hashes, "checkpoint": b.Checkpoint,
	})
}

// Decode parses a bundle, enforcing its closed schema. It is §10.1's bundle
// step 1, so whatever it refuses is `bundle`.
func Decode(raw []byte) (*Bundle, error) {
	b, err := decode(raw)
	if err != nil {
		return nil, refusal.Wrap(refusal.Bundle, err)
	}
	return b, nil
}

func decode(raw []byte) (*Bundle, error) {
	value, err := cbor.DecodeWithin(raw, MaxBundleBytes)
	if err != nil {
		// Both on the chain: ErrProof like every other refusal here, and the
		// decoder's own error, which is what Decode returned before it had one.
		return nil, fmt.Errorf("%w: not a bundle: %w", ErrProof, err)
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, proofErrorf("bundle must be a map")
	}
	allowed := map[string]bool{"v": true, "device": true, "index": true,
		"entry": true, "proof": true, "checkpoint": true}
	for key := range m {
		if !allowed[key] {
			return nil, proofErrorf("unknown field %q", key)
		}
	}
	if len(m) != len(allowed) {
		return nil, proofErrorf("bundle is missing fields")
	}
	b := &Bundle{}
	if v, ok := m["v"].(uint64); !ok || v != Version {
		return nil, proofErrorf("unsupported version")
	}
	if b.Device, ok = m["device"].(string); !ok || b.Device == "" {
		return nil, proofErrorf("device must be a non-empty text string")
	}
	index, ok := m["index"].(uint64)
	if !ok {
		return nil, proofErrorf("index must be an unsigned integer")
	}
	b.Index = int64(index)
	if b.Entry, ok = m["entry"].([]byte); !ok {
		return nil, proofErrorf("entry must be a byte string")
	}
	if b.Checkpoint, ok = m["checkpoint"].(string); !ok {
		return nil, proofErrorf("checkpoint must be a text string")
	}
	list, ok := m["proof"].([]any)
	if !ok {
		return nil, proofErrorf("proof must be an array")
	}
	for _, item := range list {
		raw, ok := item.([]byte)
		if !ok || len(raw) != len(upstream.Hash{}) {
			return nil, proofErrorf("each proof element must be a 32-byte string")
		}
		var h upstream.Hash
		copy(h[:], raw)
		b.Proof = append(b.Proof, h)
	}
	return b, nil
}

// subjectOf is the `device_id` an entry is about: an `enroll` names it inside
// the request it carries verbatim, the other device types in their body.
//
// §8.1 calls `device` "the `device_id` this bundle proves", and nothing bound
// the two. A bundle's authority is its inclusion proof, which shows the
// *entry* is in the log and says nothing about the label beside it -- so
// `device: "nas"` around another device's entry proved exactly as much as an
// honest bundle, and a consumer keying on `device` believed something no proof
// established (cold gate run 8, D25).
func subjectOf(raw []byte) (string, error) {
	env, err := entry.Decode(raw)
	if err != nil {
		return "", proofErrorf("the bundled entry does not decode: %v", err)
	}
	if env.T == "enroll" {
		body, ok := env.Body["request"].([]byte)
		if !ok {
			return "", proofErrorf("the bundled enroll carries no request")
		}
		request, err := enrollreq.Decode(body)
		if err != nil {
			return "", proofErrorf("the bundled enroll's request does not decode: %v", err)
		}
		return request.DeviceID, nil
	}
	id, ok := env.Body["device_id"].(string)
	if !ok {
		return "", proofErrorf("a bundled %q entry names no device", env.T)
	}
	return id, nil
}

// MaxBundleBytes bounds a proof bundle. It cannot be `MAX_ENTRY_BYTES`: a
// bundle *wraps* an entry that may itself be that large, plus a checkpoint and
// an inclusion proof, so the largest legal bundle necessarily exceeds the
// largest legal entry. §4.0's entry cap is §6's uint16 framing and belongs to
// entries alone (§8.1).
const MaxBundleBytes = cbor.MaxEntryBytes + 16384

// Anchor is what a reader of a bundle must already hold: the network's origin,
// its log key and its witness policy — everything in `norn.trust` that decides
// whether a checkpoint counts.
type Anchor struct {
	Origin string
	LogKey string
	Policy string
}

// Check verifies a bundle against a network's anchor.
//
// The checkpoint inside is checked exactly as §11.1 checks the ones inside
// fork evidence: this network's origin, this network's log key, **and a
// satisfied witness quorum**. §8 sells a bundle as checkable by somebody
// holding only the trust file, and a checkpoint with no corroboration proves
// only that the log said so — which is the one thing a transparency log may
// not be believed about alone. Until cold gate run 7, §8.1 asked for the log
// signature and nothing else, and two variants that skipped the quorum and the
// origin passed every vector.
//
// It deliberately does NOT consult any log. A bundle that only checks out
// while its log is reachable is not evidence.
//
// The order is §10.1's second table, and a refusal carries the code of the
// step that made it: the checkpoint, with the loop's codes from `note` to
// `quorum`; then `inclusion`; then `binding`.
func (b *Bundle) Check(anchor Anchor) error {
	cp, err := tlog.Verify(b.Checkpoint, []string{anchor.LogKey})
	if err != nil {
		return refusal.Carry(err, proofErrorf("checkpoint: %v", err))
	}
	if cp.Origin != anchor.Origin {
		return refuse(refusal.Origin, "the checkpoint is for origin %q, and this anchor is for %q",
			cp.Origin, anchor.Origin)
	}
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		return proofErrorf("the anchor's policy does not parse: %v", err)
	}
	cosignatures, err := cosign.Verify(b.Checkpoint, rules.Keys())
	if err != nil {
		return refusal.Carry(err, proofErrorf("checkpoint: %v", err))
	}
	names := make([]string, 0, len(cosignatures))
	for _, c := range cosignatures {
		if label, ok := rules.LabelFor(c.Name, c.Public); ok {
			names = append(names, label)
		}
	}
	if !rules.Satisfied(names) {
		return refuse(refusal.Quorum, "no quorum cosigned the bundle's checkpoint (quorum %q, "+
			"cosigned by %v)", rules.Quorum(), names)
	}
	if b.Index < 0 || b.Index >= cp.Size {
		return refuse(refusal.Inclusion, "index %d is outside a log of %d entries", b.Index, cp.Size)
	}
	leaf := tlog.LeafHash(b.Entry)
	if err := upstream.CheckRecord(b.Proof, cp.Size, cp.Root, b.Index, leaf); err != nil {
		return refuse(refusal.Inclusion, "inclusion proof: %v", err)
	}
	// ...and the entry the proof is about really is this device's. The proof
	// binds the entry to the log; only this binds the label to the entry. An
	// entry that names no device -- or does not decode, which a log may still
	// contain -- is about no device, so not about this one.
	subject, err := subjectOf(b.Entry)
	if err != nil {
		return refusal.Wrap(refusal.Binding, err)
	}
	if subject != b.Device {
		return refuse(refusal.Binding, "this bundle says it proves %q and carries an entry about %q",
			b.Device, subject)
	}
	return nil
}

// EntryLeafHash exposes the leaf hash a bundle commits to, for callers that
// want to cross-check it against an entry they already hold.
func (b *Bundle) EntryLeafHash() []byte { return entry.LeafHash(b.Entry) }

// noteKey renders a verifier key for an Ed25519 public key.
func noteKey(name string, public ed25519.PublicKey) string {
	return note.VerifierKey(name, public)
}
