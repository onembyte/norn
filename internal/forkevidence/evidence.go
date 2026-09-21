// Package forkevidence builds and checks the artifact a node writes when it
// catches a log signing two histories.
//
// `GOSSIP.md` part 7 says where this file goes: "the witness operators, the
// log operator's boss, or a blog post". So the bar is not that the node which
// wrote it is convinced. It is that somebody holding only `norn.trust` -- no
// running network, no reason to trust whoever is complaining -- can check it
// offline and see for themselves.
//
// Two signed heads are not enough on their own. At *different* sizes, different
// roots are exactly what a healthy log produces. What makes it a fork is a
// consistency proof showing that the larger head's own tree had a different
// root at the smaller head's size than the smaller head claims -- and because
// that proof chains to a head the log signed, the complainant cannot fabricate
// it.
package forkevidence

import (
	"errors"
	"fmt"

	upstream "golang.org/x/mod/sumdb/tlog"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/tlog"
)

// ErrEvidence reports evidence that does not prove what it claims.
var ErrEvidence = errors.New("fork evidence error")

func evidenceErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrEvidence, fmt.Sprintf(format, args...))
}

// MaxEvidenceBytes bounds an evidence file: two signed checkpoints, a
// consistency proof and the network's policy. It is stated here rather than
// inherited from §4.0, whose cap is §6's entry framing (§11.1).
const MaxEvidenceBytes = 1 << 16

// Version is the schema version of an evidence file.
const Version = 1

// Evidence is one proven equivocation.
type Evidence struct {
	// Held is the signed checkpoint the node was holding: the branch it can
	// prove things about, because it has the entries.
	Held string
	// Conflicting is the signed checkpoint that could not be reconciled with
	// it. Both are cosigned, or neither proves anything to a third party.
	Conflicting string
	// Size is where the two disagree -- the conflicting head's size.
	Size int64
	// HeldRoot is what Held's branch had at that size.
	HeldRoot []byte
	// Proof chains (Size, HeldRoot) to Held's own head, so a reader can
	// confirm the node is quoting its own log rather than inventing a root.
	// Empty when Size is Held's size, where the two signatures say it alone.
	Proof [][]byte
	// Policy is the `tlog-policy` the accuser was verifying under, carried so
	// a reader can see which witnesses were supposed to prevent this.
	//
	// It is **informational** (§11.1). A reader verifies both checkpoints
	// under its own anchor's policy and never under this one: the field comes
	// from whoever wrote the file, and §11.1's whole premise is that there is
	// no reason to trust them. `Check` used to pass it to `verified`, so an
	// accuser writing `quorum none` got two uncosigned checkpoints accepted as
	// proof of equivocation -- and §11 rule 4 makes that conclusion permanent
	// until an operator installs a new trust file.
	Policy string
}

// Finding is what a reader learns from checking evidence.
type Finding struct {
	// Size is the tree size at which the log signed two different roots.
	Size int64
	// Held and Claimed are those two roots.
	Held, Claimed [32]byte
}

// Build makes evidence from the branch a node holds and a head it cannot
// reconcile with it.
//
// It refuses to produce a file for two *consistent* heads: a node must not be
// able to accuse a log of forking by handing over its own earlier self.
// The conflicting head arrives already parsed, because the node that reached
// this point got it through the verifier: it is signed and cosigned and was
// refused only for disagreeing. Re-parsing it here would be this package
// deciding, with no keys, what it is looking at.
func Build(held *tlog.Tree, heldSigned string, conflicting string,
	conflictingCP tlog.Checkpoint) (*Evidence, error) {
	at := conflictingCP.Size
	root, err := held.HeadAt(at)
	if err != nil {
		return nil, evidenceErrorf("this node cannot speak for size %d: %v", at, err)
	}
	if root == conflictingCP.Root {
		return nil, evidenceErrorf("these two heads agree at size %d; a log and its "+
			"own earlier self is not a fork", at)
	}

	ev := &Evidence{
		Held: heldSigned, Conflicting: conflicting,
		Size: at, HeldRoot: append([]byte(nil), root[:]...),
	}
	if at != held.Size() {
		proof, err := held.ConsistencyProof(at)
		if err != nil {
			return nil, evidenceErrorf("proving this node's own branch: %v", err)
		}
		for _, hash := range proof {
			ev.Proof = append(ev.Proof, append([]byte(nil), hash[:]...))
		}
	}
	return ev, nil
}

// Check verifies evidence against a network's anchor and reports what it
// proves. Everything it needs is in the file and the trust document; nothing
// is fetched, and no part of it takes the writer's word.
//
// `readerPolicy` is the caller's own `tlog-policy` -- the trust file's, or the
// one it has replayed (§9.4). The file's own `policy` field is never used to
// decide anything; see Evidence.Policy.
func Check(ev *Evidence, origin, logVKey, readerPolicy string) (*Finding, error) {
	rules, err := policy.Parse(readerPolicy)
	if err != nil {
		return nil, evidenceErrorf("this reader's own policy does not parse: %v", err)
	}
	// The carried policy decides nothing, but a closed schema with a stated
	// grammar is part of the format: a file whose `policy` is not a policy is
	// malformed, and evidence is the artifact strangers exchange.
	if _, err := policy.Parse(ev.Policy); err != nil {
		return nil, evidenceErrorf("the carried policy is not a `tlog-policy`: %v", err)
	}
	held, err := verified(ev.Held, origin, logVKey, rules)
	if err != nil {
		return nil, evidenceErrorf("the held checkpoint: %v", err)
	}
	conflicting, err := verified(ev.Conflicting, origin, logVKey, rules)
	if err != nil {
		return nil, evidenceErrorf("the conflicting checkpoint: %v", err)
	}
	// An accuser can only speak for sizes its own branch reaches. Above that
	// there is nothing to compare, and the consistency proof refused it with a
	// message about the proof rather than about the claim (D25).
	if ev.Size > held.Size {
		return nil, evidenceErrorf("the evidence claims a disagreement at size %d and "+
			"the held branch is %d entries; an accuser can only speak for what it holds",
			ev.Size, held.Size)
	}
	if conflicting.Size != ev.Size {
		return nil, evidenceErrorf("the conflicting checkpoint is size %d, the evidence "+
			"claims a disagreement at %d", conflicting.Size, ev.Size)
	}
	if len(ev.HeldRoot) != 32 {
		return nil, evidenceErrorf("the held root is %d bytes", len(ev.HeldRoot))
	}
	var heldRoot [32]byte
	copy(heldRoot[:], ev.HeldRoot)

	// The held branch really did have this root at this size. Without this a
	// reader is taking the accuser's word for the number that matters most.
	if ev.Size != held.Size {
		proof := make(upstream.TreeProof, 0, len(ev.Proof))
		for _, hash := range ev.Proof {
			if len(hash) != 32 {
				return nil, evidenceErrorf("a proof hash is %d bytes", len(hash))
			}
			var h upstream.Hash
			copy(h[:], hash)
			proof = append(proof, h)
		}
		if err := upstream.CheckTree(proof, held.Size, held.Root, ev.Size, heldRoot); err != nil {
			return nil, evidenceErrorf("the proof does not chain %x at size %d to the "+
				"head this log signed at size %d: %v", heldRoot[:8], ev.Size,
				held.Size, err)
		}
	} else {
		if heldRoot != held.Root {
			return nil, evidenceErrorf("the evidence claims a root at size %d that is not "+
				"the one the held checkpoint is signed over", ev.Size)
		}
		// §11.1: the proof is empty at this size, because the two signatures
		// say it alone. A file carrying one anyway is a second encoding of the
		// same accusation, and evidence is the artifact strangers exchange.
		if len(ev.Proof) != 0 {
			return nil, evidenceErrorf("the evidence carries a %d-hash consistency proof "+
				"at the held checkpoint's own size, where §11.1 requires none",
				len(ev.Proof))
		}
	}

	if heldRoot == conflicting.Root {
		return nil, evidenceErrorf("both checkpoints give the same root at size %d; "+
			"nothing here is a fork", ev.Size)
	}
	return &Finding{Size: ev.Size, Held: heldRoot, Claimed: conflicting.Root}, nil
}

// verified applies everything §10 asks of a checkpoint before it counts:
// this network's origin, this network's log key, and this network's quorum.
//
// The quorum is not optional here. A log signing two things by itself is a log
// misbehaving in private; what makes a fork *provable to a third party* is
// that independent witnesses vouched for both.
func verified(signed, origin, logVKey string, rules *policy.Policy) (tlog.Checkpoint, error) {
	cp, err := tlog.Verify(signed, []string{logVKey})
	if err != nil {
		return tlog.Checkpoint{}, fmt.Errorf("not signed by this network's log key: %w", err)
	}
	if cp.Origin != origin {
		return tlog.Checkpoint{}, fmt.Errorf("origin %q is not this network's %q",
			cp.Origin, origin)
	}
	cosignatures, err := cosign.Verify(signed, rules.Keys())
	if err != nil {
		return tlog.Checkpoint{}, err
	}
	names := make([]string, 0, len(cosignatures))
	for _, c := range cosignatures {
		names = append(names, rules.Label(c.Name))
	}
	if !rules.Satisfied(names) {
		return tlog.Checkpoint{}, fmt.Errorf("no quorum cosigned it (quorum %q, "+
			"cosigned by %v); one log signing two things in private is not something "+
			"anybody else can check", rules.Quorum(), names)
	}
	return cp, nil
}

// Encode writes the evidence as deterministic CBOR (§4.0), the encoding the
// rest of this project's artifacts use.
func (e *Evidence) Encode() ([]byte, error) {
	proof := make([]any, 0, len(e.Proof))
	for _, hash := range e.Proof {
		proof = append(proof, hash)
	}
	return cbor.Encode(map[string]any{
		"version": uint64(Version), "held": e.Held, "conflicting": e.Conflicting,
		"size": uint64(e.Size), "held_root": e.HeldRoot,
		"proof": proof, "policy": e.Policy,
	})
}

// Parse reads an evidence file.
func Parse(raw []byte) (*Evidence, error) {
	value, err := cbor.DecodeWithin(raw, MaxEvidenceBytes)
	if err != nil {
		return nil, evidenceErrorf("%v", err)
	}
	doc, ok := value.(map[string]any)
	if !ok {
		return nil, evidenceErrorf("evidence is a map")
	}
	// §11.1: "a closed map of exactly these seven keys". This read the seven it
	// wanted and ignored anything else, so the closed-map rule was prose only
	// (cold gate run 8, D25). Evidence is the artifact strangers exchange; a
	// field a reader silently drops is a field an accuser can hide something in.
	allowed := map[string]bool{"version": true, "held": true, "conflicting": true,
		"size": true, "held_root": true, "proof": true, "policy": true}
	for key := range doc {
		if !allowed[key] {
			return nil, evidenceErrorf("unknown field %q", key)
		}
	}
	if len(doc) != len(allowed) {
		return nil, evidenceErrorf("evidence is missing fields")
	}
	version, _ := doc["version"].(uint64)
	if version != Version {
		return nil, evidenceErrorf("version %d, this build understands %d", version, Version)
	}
	ev := &Evidence{}
	for key, into := range map[string]*string{
		"held": &ev.Held, "conflicting": &ev.Conflicting, "policy": &ev.Policy,
	} {
		text, ok := doc[key].(string)
		if !ok {
			return nil, evidenceErrorf("%s is text", key)
		}
		*into = text
	}
	size, ok := doc["size"].(uint64)
	if !ok {
		return nil, evidenceErrorf("size is a number")
	}
	ev.Size = int64(size)
	root, ok := doc["held_root"].([]byte)
	if !ok {
		return nil, evidenceErrorf("held_root is bytes")
	}
	ev.HeldRoot = root
	hashes, ok := doc["proof"].([]any)
	if !ok {
		return nil, evidenceErrorf("proof is a list")
	}
	for _, hash := range hashes {
		raw, ok := hash.([]byte)
		if !ok {
			return nil, evidenceErrorf("a proof hash is bytes")
		}
		ev.Proof = append(ev.Proof, raw)
	}
	return ev, nil
}
