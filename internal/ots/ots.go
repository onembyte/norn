// Package ots reads OpenTimestamps `.ots` proofs.
//
// D-009 makes anchoring an **advisory** witness: it defeats backdating under
// full log-plus-witness collusion and nothing else, and it never touches the
// handshake path. So this package only ever reads, and nothing it returns can
// make a peer proven.
//
// What it can establish without asking anybody: that the operations in a proof
// really do chain from *this* checkpoint's digest to whatever each attestation
// commits to. A log that edits a checkpoint after stamping it has a proof that
// no longer chains, and that is visible offline -- no Bitcoin node, no
// calendar, no trust in the party under suspicion. Confirming that a Bitcoin
// attestation's commitment is in the block it names does need a chain, and
// this package deliberately does not pretend otherwise.
//
// The format was read off the reference implementation rather than recalled,
// and the test vector is bytes that implementation wrote.
package ots

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"

	// RIPEMD-160 is deprecated for new work, and this is not new work: the
	// OpenTimestamps format has a ripemd160 operation, and a reader that
	// refused to compute it would fail to read proofs other people's tools
	// legitimately write. Nothing here chooses a hash; it replays one.
	//lint:ignore SA1019 the format contains this operation; reading it is not using it
	"golang.org/x/crypto/ripemd160"
)

// ErrProof reports a proof that cannot be read or does not chain.
var ErrProof = errors.New("ots proof error")

func proofErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProof, fmt.Sprintf(format, args...))
}

var magic = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

// majorVersion is the only version this build understands.
const majorVersion = 1

// Operation tags.
const (
	tagSHA1      = 0x02
	tagRIPEMD160 = 0x03
	tagSHA256    = 0x08
	tagKeccak256 = 0x67
	tagAppend    = 0xf0
	tagPrepend   = 0xf1
	tagReverse   = 0xf2
	tagHexlify   = 0xf3
)

// Tree markers.
const (
	markerFork        = 0xff
	markerAttestation = 0x00
)

// Attestation tags, eight bytes each.
var (
	tagPending  = []byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
	tagBitcoin  = []byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
	tagLitecoin = []byte{0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45}
)

// Limits. A proof arrives over the network from a calendar, so every length it
// declares is somebody else's number.
const (
	maxProof    = 1 << 20
	maxOperand  = 4096
	maxDepth    = 256
	maxBranches = 1024
	maxCalendar = 1024
)

// Proof is a parsed detached timestamp file.
type Proof struct {
	// DigestOp is the hash the proof is over -- `sha256` for anything Norn
	// stamps.
	DigestOp string
	// Digest is the value the proof starts from.
	Digest []byte
	// Tree is the operation tree hanging off that digest.
	Tree *Node
}

// Node is one point in the proof: some attestations, and some operations that
// lead onwards.
type Node struct {
	Attestations []Attestation
	Steps        []Step
}

// Step is one operation and what follows it.
type Step struct {
	Op   Op
	Next *Node
}

// Op is one transformation of the running value.
type Op struct {
	Tag     byte
	Name    string
	Operand []byte
}

// Attestation is a claim about when the running value existed.
type Attestation struct {
	Tag []byte
	// Height is the block, for a chain attestation.
	Height uint64
	// Calendar is the URI, for a pending one.
	Calendar string
	// Payload is the raw attestation body, kept so an unknown attestation type
	// can still be reported rather than silently dropped.
	Payload []byte
}

// Bitcoin reports a Bitcoin block header attestation.
func (a Attestation) Bitcoin() bool { return bytes.Equal(a.Tag, tagBitcoin) }

// Pending reports an attestation still waiting at a calendar. It proves
// nothing on its own: it is a promise by a calendar to include the value.
func (a Attestation) Pending() bool { return bytes.Equal(a.Tag, tagPending) }

// Litecoin reports a Litecoin block header attestation.
func (a Attestation) Litecoin() bool { return bytes.Equal(a.Tag, tagLitecoin) }

// Kind names the attestation for a human.
func (a Attestation) Kind() string {
	switch {
	case a.Bitcoin():
		return "bitcoin"
	case a.Litecoin():
		return "litecoin"
	case a.Pending():
		return "pending"
	default:
		return "unknown"
	}
}

// Parse reads a `.ots` detached timestamp file.
func Parse(raw []byte) (*Proof, error) {
	if len(raw) > maxProof {
		return nil, proofErrorf("proof is %d bytes, more than this build will read", len(raw))
	}
	r := &reader{raw: raw}
	got, err := r.bytes(len(magic))
	if err != nil || !bytes.Equal(got, magic) {
		return nil, proofErrorf("not an OpenTimestamps proof")
	}
	version, err := r.varuint()
	if err != nil {
		return nil, err
	}
	if version != majorVersion {
		return nil, proofErrorf("major version %d, this build reads %d", version, majorVersion)
	}
	op, err := r.byte()
	if err != nil {
		return nil, err
	}
	name, size, ok := digestOp(op)
	if !ok {
		return nil, proofErrorf("the file hash op %#x is not a hash this build knows", op)
	}
	digest, err := r.bytes(size)
	if err != nil {
		return nil, err
	}
	tree, err := r.node(0)
	if err != nil {
		return nil, err
	}
	if r.left() != 0 {
		return nil, proofErrorf("%d bytes after the end of the proof", r.left())
	}
	return &Proof{DigestOp: name, Digest: digest, Tree: tree}, nil
}

// Attestations lists every attestation in the proof, in tree order.
func (p *Proof) Attestations() []Attestation {
	var out []Attestation
	var walk func(*Node)
	walk = func(n *Node) {
		if n == nil {
			return
		}
		out = append(out, n.Attestations...)
		for _, step := range n.Steps {
			walk(step.Next)
		}
	}
	walk(p.Tree)
	return out
}

// Result is one attestation with the value it commits to.
type Result struct {
	Attestation Attestation
	// Commitment is the value that reached this attestation after every
	// operation on the path from the digest.
	Commitment []byte
}

// Walk applies the proof's operations to `digest` and returns what each
// attestation ends up committing to.
//
// This is the whole offline check. It says "these operations, starting from
// this checkpoint, produce these values" -- and a checkpoint that was edited
// after stamping produces different ones. It does **not** say the values are
// in any block; that needs a chain, and claiming it here would be the kind of
// borrowed confidence this project exists to avoid.
func (p *Proof) Walk(digest []byte) ([]Result, error) {
	if !bytes.Equal(digest, p.Digest) {
		return nil, proofErrorf("this proof is over %x…, not %x… -- it was made for a "+
			"different document", p.Digest[:4], digest[:min(4, len(digest))])
	}
	var out []Result
	var walk func(*Node, []byte, int) error
	walk = func(n *Node, value []byte, depth int) error {
		if n == nil {
			return nil
		}
		if depth > maxDepth {
			return proofErrorf("proof nests more than %d deep", maxDepth)
		}
		for _, a := range n.Attestations {
			out = append(out, Result{Attestation: a,
				Commitment: append([]byte(nil), value...)})
		}
		for _, step := range n.Steps {
			next, err := apply(step.Op, value)
			if err != nil {
				return err
			}
			if err := walk(step.Next, next, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(p.Tree, append([]byte(nil), digest...), 0); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, proofErrorf("the proof attests to nothing")
	}
	return out, nil
}

// apply runs one operation.
func apply(op Op, value []byte) ([]byte, error) {
	switch op.Tag {
	case tagAppend:
		return append(append([]byte(nil), value...), op.Operand...), nil
	case tagPrepend:
		return append(append([]byte(nil), op.Operand...), value...), nil
	case tagSHA256:
		sum := sha256.Sum256(value)
		return sum[:], nil
	case tagSHA1:
		sum := sha1.Sum(value) //nolint:gosec // the format has it; it is not a security choice here
		return sum[:], nil
	case tagRIPEMD160:
		h := ripemd160.New()
		_, _ = h.Write(value)
		return h.Sum(nil), nil
	case tagReverse:
		out := make([]byte, len(value))
		for i, b := range value {
			out[len(value)-1-i] = b
		}
		return out, nil
	case tagHexlify:
		return []byte(fmt.Sprintf("%x", value)), nil
	default:
		return nil, proofErrorf("operation %#x is not one this build can apply", op.Tag)
	}
}

// digestOp names a hash op and gives its digest length.
func digestOp(tag byte) (string, int, bool) {
	switch tag {
	case tagSHA256:
		return "sha256", 32, true
	case tagSHA1:
		return "sha1", 20, true
	case tagRIPEMD160:
		return "ripemd160", 20, true
	case tagKeccak256:
		return "keccak256", 32, true
	default:
		return "", 0, false
	}
}

// reader walks the serialized proof.
type reader struct {
	raw []byte
	at  int
}

func (r *reader) left() int { return len(r.raw) - r.at }

func (r *reader) byte() (byte, error) {
	if r.at >= len(r.raw) {
		return 0, proofErrorf("the proof ends in the middle of itself")
	}
	b := r.raw[r.at]
	r.at++
	return b, nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 || r.left() < n {
		return nil, proofErrorf("the proof claims %d more bytes than it has", n)
	}
	out := r.raw[r.at : r.at+n]
	r.at += n
	return out, nil
}

// varuint is the format's LEB128: seven bits a byte, high bit continues.
func (r *reader) varuint() (uint64, error) {
	var value uint64
	var shift uint
	for {
		b, err := r.byte()
		if err != nil {
			return 0, err
		}
		if shift > 63 {
			return 0, proofErrorf("a length does not fit in 64 bits")
		}
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, nil
		}
		shift += 7
	}
}

func (r *reader) varbytes(max int) ([]byte, error) {
	n, err := r.varuint()
	if err != nil {
		return nil, err
	}
	if n > uint64(max) {
		return nil, proofErrorf("a %d-byte field, more than the %d this build reads", n, max)
	}
	return r.bytes(int(n))
}

// node reads a timestamp subtree.
//
// The shape: any number of `0xff`-prefixed branches, then one unprefixed final
// branch. A branch is either `0x00` and an attestation, or an operation and
// the subtree that follows it.
func (r *reader) node(depth int) (*Node, error) {
	if depth > maxDepth {
		return nil, proofErrorf("proof nests more than %d deep", maxDepth)
	}
	n := &Node{}
	for branches := 0; ; branches++ {
		if branches > maxBranches {
			return nil, proofErrorf("proof has more than %d branches", maxBranches)
		}
		tag, err := r.byte()
		if err != nil {
			return nil, err
		}
		if tag != markerFork {
			// The last branch of this node.
			return n, r.branch(n, tag, depth)
		}
		next, err := r.byte()
		if err != nil {
			return nil, err
		}
		if err := r.branch(n, next, depth); err != nil {
			return nil, err
		}
	}
}

// branch reads one branch, given the tag that opened it.
func (r *reader) branch(n *Node, tag byte, depth int) error {
	if tag == markerAttestation {
		a, err := r.attestation()
		if err != nil {
			return err
		}
		n.Attestations = append(n.Attestations, a)
		return nil
	}
	op, err := r.op(tag)
	if err != nil {
		return err
	}
	next, err := r.node(depth + 1)
	if err != nil {
		return err
	}
	n.Steps = append(n.Steps, Step{Op: op, Next: next})
	return nil
}

// op reads one operation, given its tag.
func (r *reader) op(tag byte) (Op, error) {
	switch tag {
	case tagAppend, tagPrepend:
		operand, err := r.varbytes(maxOperand)
		if err != nil {
			return Op{}, err
		}
		name := "append"
		if tag == tagPrepend {
			name = "prepend"
		}
		return Op{Tag: tag, Name: name, Operand: operand}, nil
	case tagSHA256, tagSHA1, tagRIPEMD160, tagKeccak256, tagReverse, tagHexlify:
		name, _, _ := digestOp(tag)
		if name == "" {
			name = map[byte]string{tagReverse: "reverse", tagHexlify: "hexlify"}[tag]
		}
		return Op{Tag: tag, Name: name}, nil
	default:
		return Op{}, proofErrorf("operation tag %#x is not one this build knows", tag)
	}
}

// attestation reads an eight-byte tag and its payload.
func (r *reader) attestation() (Attestation, error) {
	tag, err := r.bytes(8)
	if err != nil {
		return Attestation{}, err
	}
	payload, err := r.varbytes(maxCalendar + 16)
	if err != nil {
		return Attestation{}, err
	}
	a := Attestation{Tag: append([]byte(nil), tag...),
		Payload: append([]byte(nil), payload...)}

	inner := &reader{raw: payload}
	switch {
	case a.Bitcoin(), a.Litecoin():
		height, err := inner.varuint()
		if err != nil {
			return Attestation{}, proofErrorf("a chain attestation with no block height")
		}
		a.Height = height
	case a.Pending():
		uri, err := inner.varbytes(maxCalendar)
		if err != nil {
			return Attestation{}, proofErrorf("a pending attestation with no calendar")
		}
		a.Calendar = string(uri)
	}
	return a, nil
}
