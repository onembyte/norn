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
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
)

// Version is the bundle format version.
const Version = uint64(1)

// ErrProof reports a bundle that is malformed or does not check out.
var ErrProof = errors.New("proof bundle error")

func proofErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProof, fmt.Sprintf(format, args...))
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

// Decode parses a bundle, enforcing its closed schema.
func Decode(raw []byte) (*Bundle, error) {
	value, err := cbor.Decode(raw)
	if err != nil {
		return nil, err
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

// Check verifies the bundle against the given log verifier keys: the
// checkpoint's signature, then that this entry really is at this index in a
// tree with that root.
//
// It deliberately does NOT consult any log. A bundle that only checks out
// while its log is reachable is not evidence.
func (b *Bundle) Check(logKeys []string) error {
	cp, err := tlog.Verify(b.Checkpoint, logKeys)
	if err != nil {
		return proofErrorf("checkpoint: %v", err)
	}
	if b.Index < 0 || b.Index >= cp.Size {
		return proofErrorf("index %d is outside a log of %d entries", b.Index, cp.Size)
	}
	leaf := tlog.LeafHash(b.Entry)
	if err := upstream.CheckRecord(b.Proof, cp.Size, cp.Root, b.Index, leaf); err != nil {
		return proofErrorf("inclusion proof: %v", err)
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
