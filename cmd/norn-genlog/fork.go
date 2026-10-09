// These vectors write the fork directory.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/onembyte/norn/internal/cbor"
	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

// writeForkEvidence builds a second branch of this network and the evidence
// that proves the two cannot both be its log.
//
// The branch diverges at `forkAt` and is signed and cosigned exactly as
// correctly as the real one -- which is the whole difficulty of a fork: every
// signature checks out, and only holding both heads reveals it.
func writeForkEvidence(root, origin string, key ed25519.PrivateKey,
	entries [][]byte, heldSigned string, held *tlogstore.Store) error {
	// A prefix is not a fork -- `forkevidence.Build` refuses one, which is the
	// guard that stopped this vector being wrong the first time it was
	// generated. The branch has to *diverge*: the same history up to `forkAt`,
	// then an entry this network never carried.
	signers, err := witnessSigners(root)
	if err != nil {
		return err
	}
	forkedSigned, forkedCP, err := forkedBranch(root, origin, key, entries, signers, forkAt+1)
	if err != nil {
		return err
	}

	heldTree, err := tlog.Build(entries)
	if err != nil {
		return err
	}
	evidence, err := forkevidence.Build(heldTree, heldSigned, forkedSigned, forkedCP)
	if err != nil {
		return err
	}
	evidence.Policy = policyOf(root)

	raw, err := evidence.Encode()
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "fork")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence.cbor"), raw, 0o644); err != nil {
		return err
	}
	// The conflicting head on its own too, so a reader can see what the
	// evidence is about without decoding anything.
	if err := os.WriteFile(filepath.Join(dir, "conflicting.checkpoint"),
		[]byte(forkedSigned), 0o644); err != nil {
		return err
	}
	// Cold gate run 12, D13a. RFC 6962's consistency proof takes its own
	// branch when the smaller size is a power of two, and the only sound
	// evidence was at 41, so a reader that dropped that branch passed every
	// file. This one is at 64, below a held branch of 127.
	signed64, cp64, err := forkedBranch(root, origin, key, entries, signers, 64)
	if err != nil {
		return err
	}
	at64, err := forkevidence.Build(heldTree, heldSigned, signed64, cp64)
	if err != nil {
		return err
	}
	at64.Policy = policyOf(root)
	raw64, err := at64.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-at-64.cbor"), raw64, 0o644); err != nil {
		return err
	}
	// Cold gate run 13, D14. The two signed roots prove a same-size fork
	// without a consistency path. Every previous same-size file was refused.
	sameSigned, sameCP, err := forkedBranch(root, origin, key, entries, signers, len(entries))
	if err != nil {
		return err
	}
	same, err := forkevidence.Build(heldTree, heldSigned, sameSigned, sameCP)
	if err != nil {
		return err
	}
	same.Policy = policyOf(root)
	rawSame, err := same.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-at-same-size.cbor"), rawSame, 0o644); err != nil {
		return err
	}
	return writeForkNegatives(root, origin, key, entries, heldSigned, heldTree, signers,
		evidence, forkedSigned, forkedCP)
}

// forkedBranch is a branch of `size` entries that agrees with `entries` up to
// its last entry and then carries one this network never did, signed by the
// log key and cosigned exactly as correctly as the real head -- the whole
// difficulty of a fork: every signature checks out, and only holding both
// heads reveals it.
func forkedBranch(root, origin string, key ed25519.PrivateKey, entries [][]byte,
	signers []cosignpkg.Signer, size int) (string, tlog.Checkpoint, error) {
	if size < 1 || size-1 > len(entries) {
		return "", tlog.Checkpoint{}, fmt.Errorf("a branch of %d cannot share %d entries' history",
			size, len(entries))
	}
	branch := append([][]byte(nil), entries[:size-1]...)
	divergent, err := forkEntry(root)
	if err != nil {
		return "", tlog.Checkpoint{}, err
	}
	signed, err := signedHeadOver(root, origin, key, append(branch, divergent), signers)
	if err != nil {
		return "", tlog.Checkpoint{}, err
	}
	cp, err := tlog.Verify(signed, []string{note.VerifierKey(origin,
		key.Public().(ed25519.PublicKey))})
	return signed, cp, err
}

// writeForkNegatives ships the two refusals §12.1 has claimed since Phase 4.
// Neither existed as a file: the first was exercised by a Go test against the
// *valid* vector, and the second could not be exercised at all, because
// `forkevidence.Build` refuses to produce it. A reader given only this
// directory could check that a fork is proved and nothing about what is not.
func writeForkNegatives(root, origin string, key ed25519.PrivateKey,
	entries [][]byte, heldSigned string, heldTree *tlog.Tree,
	signers []cosignpkg.Signer, evidence *forkevidence.Evidence,
	forkedSigned string, forkedCP tlog.Checkpoint) error {

	dir := filepath.Join(root, "fork")

	// 1. A log and its own earlier self. Every signature is valid, both heads
	// are cosigned, and the roots agree at the smaller size -- which is
	// exactly why it is not a fork. `Build` refuses to make this, so it is
	// assembled by hand: the accusation a node must never be able to publish.
	prefixAt := int64(len(entries)) - 10
	prefixSigned, err := signedHeadOver(root, origin, key, entries[:prefixAt], signers)
	if err != nil {
		return err
	}
	rootAt, err := heldTree.HeadAt(prefixAt)
	if err != nil {
		return err
	}
	consistent := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: prefixSigned,
		Size: prefixAt, HeldRoot: append([]byte(nil), rootAt[:]...),
		Policy: policyOf(root),
	}
	proof, err := heldTree.ConsistencyProof(prefixAt)
	if err != nil {
		return err
	}
	for _, hash := range proof {
		consistent.Proof = append(consistent.Proof, append([]byte(nil), hash[:]...))
	}
	raw, err := consistent.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-consistent.cbor"), raw, 0o644); err != nil {
		return err
	}

	// 2. A real fork, of a different network. Perfectly valid evidence, and
	// none of this anchor's business: an accusation a reader must not accept
	// on behalf of a log it is not about.
	elsewhere := "norn/elsewhere"
	elsewhereEntries := append([][]byte(nil), entries[:forkAt]...)
	divergent, err := forkEntry(root)
	if err != nil {
		return err
	}
	branchA, err := signedHeadOver(root, elsewhere, key, elsewhereEntries, signers)
	if err != nil {
		return err
	}
	branchB, err := signedHeadOver(root, elsewhere, key,
		append(append([][]byte(nil), elsewhereEntries...), divergent), signers)
	if err != nil {
		return err
	}
	treeA, err := tlog.Build(elsewhereEntries)
	if err != nil {
		return err
	}
	cpB, err := tlog.Verify(branchB, []string{note.VerifierKey(elsewhere,
		key.Public().(ed25519.PublicKey))})
	if err != nil {
		return err
	}
	_ = cpB
	// Their heads differ at the shorter size, which is what makes it evidence
	// over there and irrelevant here.
	other := &forkevidence.Evidence{
		Held: branchB, Conflicting: branchA, Size: treeA.Size(),
		Policy: policyOf(root),
	}
	treeB, err := tlog.Build(append(append([][]byte(nil), elsewhereEntries...), divergent))
	if err != nil {
		return err
	}
	rootB, err := treeB.HeadAt(treeA.Size())
	if err != nil {
		return err
	}
	other.HeldRoot = append([]byte(nil), rootB[:]...)
	proofB, err := treeB.ConsistencyProof(treeA.Size())
	if err != nil {
		return err
	}
	for _, hash := range proofB {
		other.Proof = append(other.Proof, append([]byte(nil), hash[:]...))
	}
	rawOther, err := other.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-other-origin.cbor"), rawOther, 0o644); err != nil {
		return err
	}

	// Cold gate run 6, H1: the two cases above land on §11.1's steps 1 and 4,
	// and nothing in the suite reached steps 2 or 3. A reader that never
	// checked the consistency proof, never verified the *conflicting*
	// checkpoint, or never compared the sizes passed every vector -- and §11
	// rule 4 makes a concluded fork permanent, so a forged accusation any
	// stranger can write is a permanent denial of service.
	//
	// Each of these three must get *past* the earlier steps, or it tests one
	// of those instead.

	// Step 3. Both checkpoints verify, the sizes agree, and the proof does not
	// chain: an invented root at a size the accuser cannot speak for.
	forged := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: forkedSigned,
		Size: forkedCP.Size, Policy: policyOf(root),
	}
	invented := sha256.Sum256([]byte("norn/fork/an invented held root"))
	forged.HeldRoot = append([]byte(nil), invented[:]...)
	for _, hash := range evidence.Proof {
		forged.Proof = append(forged.Proof, append([]byte(nil), hash...))
	}
	if len(forged.Proof) == 0 {
		return fmt.Errorf("the fork vector's proof is empty; a forged one would prove nothing")
	}
	forged.Proof[0][0] ^= 0x01
	rawForged, err := forged.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-forged-proof.cbor"), rawForged, 0o644); err != nil {
		return err
	}

	// Step 1, the half nothing covered: the *held* checkpoint is this
	// network's and verifies; the conflicting one is cosigned by nobody, so a
	// reader that only checks the accuser's own head accepts it.
	uncosigned, err := note.Sign(mustBody(forkedSigned), origin, key)
	if err != nil {
		return err
	}
	halfVerified := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: uncosigned,
		Size: forkedCP.Size, HeldRoot: append([]byte(nil), evidence.HeldRoot...),
		Proof: evidence.Proof, Policy: policyOf(root),
	}
	rawHalf, err := halfVerified.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-unverifiable-conflicting.cbor"),
		rawHalf, 0o644); err != nil {
		return err
	}

	// Step 2. Both checkpoints verify; the file claims a disagreement at a
	// size the conflicting head does not have.
	mismatched := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: forkedSigned,
		Size: forkedCP.Size - 1, HeldRoot: append([]byte(nil), evidence.HeldRoot...),
		Proof: evidence.Proof, Policy: policyOf(root),
	}
	rawMismatch, err := mismatched.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-size-mismatch.cbor"),
		rawMismatch, 0o644); err != nil {
		return err
	}

	// §11.1 requires an empty `proof` when the disagreement is at the held
	// checkpoint's own size: the two signatures say it alone. A file carrying
	// one anyway is a second encoding of the same accusation, and nothing
	// refused it.
	sameSize, err := signedHeadOver(root, origin, key, sameSizeBranch(entries, divergent), signers)
	if err != nil {
		return err
	}
	sameSizeCP, err := tlog.Verify(sameSize, []string{note.VerifierKey(origin,
		key.Public().(ed25519.PublicKey))})
	if err != nil {
		return err
	}
	if sameSizeCP.Size != int64(len(entries)) {
		return fmt.Errorf("the same-size branch is %d entries, the held log is %d",
			sameSizeCP.Size, len(entries))
	}
	atSameSize := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: sameSize, Size: sameSizeCP.Size,
		HeldRoot: heldHeadBytes(heldTree),
		Proof:    [][]byte{append([]byte(nil), evidence.HeldRoot...)},
		Policy:   policyOf(root),
	}
	rawSameSize, err := atSameSize.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-proof-at-same-size.cbor"),
		rawSameSize, 0o644); err != nil {
		return err
	}

	// Cold gate run 7, J12. §11.1 gave `policy` no validation rule, and the
	// reader verified BOTH checkpoints under it -- the witness keys from its
	// own trust file, the quorum from the accuser's. An accuser writing
	// `quorum none` therefore got two uncosigned checkpoints accepted as proof
	// of equivocation, and §11 rule 4 makes that conclusion permanent until an
	// operator installs a new trust file. A permanent, network-wide denial of
	// service from a file, with no keys and no access to anything.
	heldUncosigned, err := note.Sign(mustBody(heldSigned), origin, key)
	if err != nil {
		return err
	}
	permissive := &forkevidence.Evidence{
		Held: heldUncosigned, Conflicting: uncosigned,
		Size: forkedCP.Size, HeldRoot: append([]byte(nil), evidence.HeldRoot...),
		Proof: evidence.Proof, Policy: quorumNonePolicy(root),
	}
	rawPermissive, err := permissive.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-policy-says-quorum-none.cbor"),
		rawPermissive, 0o644); err != nil {
		return err
	}

	// The field is a closed-schema text with a stated grammar, so it must
	// parse even though it decides nothing.
	unparseable := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: forkedSigned,
		Size: forkedCP.Size, HeldRoot: append([]byte(nil), evidence.HeldRoot...),
		Proof: evidence.Proof, Policy: "this is not a tlog-policy\n",
	}
	rawUnparseable, err := unparseable.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-policy-unparseable.cbor"),
		rawUnparseable, 0o644); err != nil {
		return err
	}

	// Cold gate run 13, D4. The closed-code table checks the carried policy
	// at step 4, then held at step 5. Both faults must be present to pin it.
	twoFaults := *unparseable
	twoFaults.Held, err = signedHeadOver(root, elsewhere, key, entries, signers)
	if err != nil {
		return err
	}
	rawTwoFaults, err := twoFaults.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-policy-unparseable-and-foreign-held.cbor"), rawTwoFaults, 0o644); err != nil {
		return err
	}

	// ...and the other direction, which is a POSITIVE case: a carried policy
	// the reader does not share must not break evidence that is otherwise
	// sound. A reader that verified under the field would refuse a real fork
	// and skip the alarm §11 rule 1 requires.
	ghost, err := seedKey(root, "stranger")
	if err != nil {
		return err
	}
	foreign := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: forkedSigned,
		Size: forkedCP.Size, HeldRoot: append([]byte(nil), evidence.HeldRoot...),
		Proof: evidence.Proof, Policy: unmeetablePolicy(root, ghost),
	}
	rawForeign, err := foreign.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "policy-not-the-readers.cbor"),
		rawForeign, 0o644); err != nil {
		return err
	}

	// Cold gate run 8, D25. §11.1 calls this "a closed map of exactly these
	// seven keys" and `Parse` read the seven it wanted, ignoring the rest --
	// so the rule was prose only. Evidence is the artifact strangers exchange;
	// a field a reader silently drops is one an accuser can hide something in.
	if err := os.WriteFile(filepath.Join(dir, "bad-open-schema.cbor"),
		withExtraKey(raw, "surprise", "an unpermitted evidence key"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-wrong-version.cbor"),
		withVersion(raw, 2), 0o644); err != nil {
		return err
	}
	// 6.5l-vii-b-ii. Built, like the two above, on `raw` -- the bad-consistent
	// evidence -- so it fails three steps: `version`, the key set, and
	// `consistent`. §11.1's order decides: `version` comes before the key set,
	// because a key set is only closed relative to a version. A reader that
	// checks the keys first says `schema`, which is what this repository's own
	// reader said until this file existed.
	if err := os.WriteFile(filepath.Join(dir, "bad-version-and-unknown-key.cbor"),
		withVersion(withExtraKey(raw, "surprise", "a key version 1 does not have"), 2),
		0o644); err != nil {
		return err
	}
	// §11.1 types `held_root` as `bytes (32)`, so a 31-byte one is a step-3
	// schema fault -- and this file is also an accusation about a size its
	// accuser cannot reach, a step-7 fault. A reader that measures the root
	// only once it has checked the size answers `size`.
	shortRoot := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: forkedSigned,
		Size: int64(len(entries)) + 1, HeldRoot: append([]byte(nil), evidence.HeldRoot[:31]...),
		Proof: evidence.Proof, Policy: policyOf(root),
	}
	rawShortRoot, err := shortRoot.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-short-held-root-and-size-above-held.cbor"),
		rawShortRoot, 0o644); err != nil {
		return err
	}
	// 6.5l-vii-b-iii. §11.1 says the size bound is checked "before any parse",
	// and bad-oversize parses: a reader that decodes first and measures after
	// refuses it too, as `oversize`. Here the bytes are not CBOR either, so a
	// parse-first reader answers `cbor`.
	if err := os.WriteFile(filepath.Join(dir, "bad-oversize-and-not-cbor.cbor"),
		bytes.Repeat([]byte{0xff}, forkevidence.MaxEvidenceBytes+1), 0o644); err != nil {
		return err
	}
	// §11.1 step 1, which no file reached: the SOUND evidence -- not `raw`,
	// which is bad-consistent -- with `size` written in a longer form than the
	// shortest (§4.0). A decoder that accepts any well-formed CBOR proves the
	// fork from it; a reader of deterministic CBOR refuses it as `cbor`.
	sound, err := evidence.Encode()
	if err != nil {
		return err
	}
	if evidence.Size < 24 || evidence.Size > 0xff {
		return fmt.Errorf("the non-canonical case widens a one-byte size argument; size is %d",
			evidence.Size)
	}
	shortest := []byte{0x64, 's', 'i', 'z', 'e', 0x18, byte(evidence.Size)}
	widened := []byte{0x64, 's', 'i', 'z', 'e', 0x19, 0x00, byte(evidence.Size)}
	if bytes.Count(sound, shortest) != 1 {
		return fmt.Errorf("the sound evidence does not encode size %d exactly once in "+
			"its shortest form", evidence.Size)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-non-canonical-cbor.cbor"),
		bytes.Replace(sound, shortest, widened, 1), 0o644); err != nil {
		return err
	}
	// A proof hash of 31 bytes. Everything else is the sound evidence, so a
	// reader that leaves the length to the proof check refuses it too -- as
	// `proof`, where §11.1 says `schema`.
	shortHash := append([][]byte(nil), evidence.Proof...)
	shortHash[0] = append([]byte(nil), evidence.Proof[0][:31]...)
	shortProof := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: forkedSigned,
		Size: forkedCP.Size, HeldRoot: append([]byte(nil), evidence.HeldRoot...),
		Proof: shortHash, Policy: policyOf(root),
	}
	rawShortProof, err := shortProof.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-short-proof-hash.cbor"),
		rawShortProof, 0o644); err != nil {
		return err
	}
	// An accuser can only speak for sizes its own branch reaches. The
	// conflicting head really is `size` entries -- cold gate run 12 (D17)
	// found it was the 41-entry one, so step 7's other half ("conflicting's
	// size equals `size`") refused it too and its own rule was not isolated.
	beyondSigned, _, err := forkedBranch(root, origin, key, entries, signers, len(entries)+1)
	if err != nil {
		return err
	}
	aboveHeld := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: beyondSigned,
		Size: int64(len(entries)) + 1, HeldRoot: append([]byte(nil), evidence.HeldRoot...),
		Proof: evidence.Proof, Policy: policyOf(root),
	}
	rawAbove, err := aboveHeld.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-size-above-held.cbor"),
		rawAbove, 0o644); err != nil {
		return err
	}

	// Cold gate run 12, D2. At the held size there is no proof to check, and
	// what binds `held_root` to anything is that it is the root `held` is
	// signed over. Both checkpoints here are the one honest head; `held_root`
	// is 32 arbitrary bytes. A reader that skips the comparison proves a fork
	// from one honest checkpoint -- permanently, by §11 rule 4.
	forgedRoot := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: heldSigned, Size: int64(len(entries)),
		HeldRoot: bytes.Repeat([]byte{0x42}, 32), Policy: policyOf(root),
	}
	rawForgedRoot, err := forgedRoot.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-held-root-at-same-size.cbor"),
		rawForgedRoot, 0o644); err != nil {
		return err
	}
	// Cold gate run 12, D3. A cosigned size-0 head, and evidence claiming a
	// disagreement at size 0. No consistency proof starts at an empty tree and
	// every log has the same root there; a reader that lets an empty proof
	// stand proves a fork from any old size-0 checkpoint.
	emptySigned, err := signedHeadOver(root, origin, key, nil, signers)
	if err != nil {
		return err
	}
	atZero := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: emptySigned, Size: 0,
		HeldRoot: bytes.Repeat([]byte{0x42}, 32), Policy: policyOf(root),
	}
	rawAtZero, err := atZero.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-size-zero.cbor"), rawAtZero, 0o644); err != nil {
		return err
	}

	// Cold gate run 12, D16. bad-oversize is thousands of bytes over and
	// bad-oversize-and-not-cbor is not evidence, so a cap one byte off in
	// either direction passed. Exactly at the cap, sound: it MUST prove the
	// fork (it is in `sound`). Exactly one byte past, sound in every other
	// respect: `oversize` -- and a reader whose cap is one byte too lax
	// decodes it and proves the fork from it.
	atCap, err := evidenceOfSize(root, evidence, forkevidence.MaxEvidenceBytes)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-at-the-cap.cbor"), atCap, 0o644); err != nil {
		return err
	}
	onePast, err := evidenceOfSize(root, evidence, forkevidence.MaxEvidenceBytes+1)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-one-past-the-cap.cbor"), onePast, 0o644); err != nil {
		return err
	}

	// Cold gate run 9, D8. §11.1 states MAX_EVIDENCE_BYTES and calls its bound
	// the thing that "matters more here than anywhere else in the document",
	// and nothing in the suite was ever close -- a reader with a cap of a
	// million passed everything. Padded through the one field with room: a
	// `witness` URL, which the policy grammar does not bound. The file is
	// correct in every other respect, so only its size can refuse it.
	padded := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: forkedSigned,
		Size: forkedCP.Size, HeldRoot: append([]byte(nil), evidence.HeldRoot...),
		Proof: evidence.Proof, Policy: hugePolicy(root),
	}
	rawPadded, err := padded.Encode()
	if err != nil {
		return err
	}
	if len(rawPadded) <= forkevidence.MaxEvidenceBytes {
		return fmt.Errorf("the oversize evidence case is %d bytes and the cap is %d",
			len(rawPadded), forkevidence.MaxEvidenceBytes)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-oversize.cbor"),
		rawPadded, 0o644); err != nil {
		return err
	}

	// Cold gate run 13, D22. Booleans are valid CBOR profile items; the
	// evidence schema still requires `size` to be an unsigned integer. Start
	// with sound evidence so this file reaches that schema check with every
	// other field and proof intact.
	rawBoolSize, err := evidence.Encode()
	if err != nil {
		return err
	}
	decodedBoolSize, err := cbor.DecodeWithin(rawBoolSize, forkevidence.MaxEvidenceBytes)
	if err != nil {
		return err
	}
	boolSizeMap, ok := decodedBoolSize.(map[string]any)
	if !ok {
		return fmt.Errorf("sound fork evidence decoded as %T, want map", decodedBoolSize)
	}
	boolSizeMap["size"] = true
	rawBoolSize, err = cbor.Encode(boolSizeMap)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-bool-size.cbor"),
		rawBoolSize, 0o644); err != nil {
		return err
	}

	// `says` is what §12 makes it, a semantic hint. These are the phrases
	// each case carried until 6.5l-vi-b-iv overwrote them with code names --
	// two reworded to match the refusal as it now reads: the oversize
	// check names MAX_EVIDENCE_BYTES, and an unsupported version says so.
	// The codes live in `codes` (6.5l-vii-b-i).
	forkCases := []map[string]string{
		{"name": "bad-oversize", "says": "MAX_EVIDENCE_BYTES"},
		{"name": "bad-open-schema", "says": "unknown field"},
		{"name": "bad-wrong-version", "says": "unsupported version"},
		{"name": "bad-version-and-unknown-key", "says": "unsupported version"},
		{"name": "bad-short-held-root-and-size-above-held", "says": "held_root is 31 bytes"},
		{"name": "bad-short-proof-hash", "says": "a proof hash is 31 bytes"},
		{"name": "bad-oversize-and-not-cbor", "says": "MAX_EVIDENCE_BYTES"},
		{"name": "bad-non-canonical-cbor", "says": "not valid deterministic CBOR"},
		{"name": "bad-held-root-at-same-size", "says": "not the one the held checkpoint is signed over"},
		{"name": "bad-size-zero", "says": "at size 0"},
		{"name": "bad-one-past-the-cap", "says": "MAX_EVIDENCE_BYTES"},
		{"name": "bad-size-above-held", "says": "can only speak for what it holds"},
		{"name": "bad-bool-size", "says": "size is bool, want uint"},
		{"name": "bad-policy-says-quorum-none", "says": "no quorum cosigned it"},
		{"name": "bad-policy-unparseable", "says": "not a `tlog-policy`"},
		{"name": "bad-policy-unparseable-and-foreign-held", "says": "not a `tlog-policy`"},
		{"name": "bad-proof-at-same-size", "says": "requires none"},
		{"name": "bad-consistent", "says": "nothing here is a fork"},
		{"name": "bad-other-origin", "says": "the held checkpoint"},
		{"name": "bad-forged-proof", "says": "does not chain"},
		{"name": "bad-unverifiable-conflicting", "says": "the conflicting checkpoint"},
		{"name": "bad-size-mismatch", "says": "claims a disagreement"},
	}
	// D-061: the §11.1 code each is refused with, the first failing step
	// deciding. bad-policy-says-quorum-none is `held`: the carried policy
	// parses, and the held checkpoint fails the reader's OWN quorum.
	forkCodes := map[string]evrefusal.Code{
		"bad-oversize":                            evrefusal.Oversize,
		"bad-open-schema":                         evrefusal.Schema,
		"bad-wrong-version":                       evrefusal.Version,
		"bad-version-and-unknown-key":             evrefusal.Version,
		"bad-short-held-root-and-size-above-held": evrefusal.Schema,
		"bad-short-proof-hash":                    evrefusal.Schema,
		"bad-oversize-and-not-cbor":               evrefusal.Oversize,
		"bad-non-canonical-cbor":                  evrefusal.CBOR,
		"bad-held-root-at-same-size":              evrefusal.Proof,
		"bad-size-zero":                           evrefusal.Proof,
		"bad-one-past-the-cap":                    evrefusal.Oversize,
		"bad-size-above-held":                     evrefusal.Size,
		"bad-bool-size":                           evrefusal.Schema,
		"bad-policy-says-quorum-none":             evrefusal.Held,
		"bad-policy-unparseable":                  evrefusal.Policy,
		"bad-policy-unparseable-and-foreign-held": evrefusal.Policy,
		"bad-proof-at-same-size":                  evrefusal.Proof,
		"bad-consistent":                          evrefusal.Consistent,
		"bad-other-origin":                        evrefusal.Held,
		"bad-forged-proof":                        evrefusal.Proof,
		"bad-unverifiable-conflicting":            evrefusal.Conflicting,
		"bad-size-mismatch":                       evrefusal.Size,
	}
	if err := checkCodes("fork", namesOf(forkCases), forkCodes, evrefusal.Known); err != nil {
		return err
	}

	manifest := map[string]any{
		"rules": map[string]map[string]string{
			"bad-oversize":                            {"section": "11.1", "says": "MAX_EVIDENCE_BYTES"},
			"bad-open-schema":                         {"section": "11.1", "says": "a closed map of exactly these seven keys"},
			"bad-wrong-version":                       {"section": "11.1", "says": "| `version` | uint | `1` or `2` |"},
			"bad-version-and-unknown-key":             {"section": "11.1", "says": "a key set is only closed relative to a version"},
			"bad-short-held-root-and-size-above-held": {"section": "11.1", "says": "| `held_root` | bytes (32) |"},
			"bad-short-proof-hash":                    {"section": "11.1", "says": "| `proof` | array of bytes (32 each) |"},
			"bad-oversize-and-not-cbor":               {"section": "11.1", "says": "the size bound is checked before any parse"},
			"bad-non-canonical-cbor":                  {"section": "11.1", "says": "the file is not valid deterministic CBOR"},
			"bad-held-root-at-same-size":              {"section": "11.1", "says": "`held_root` is not the root the held checkpoint is signed over"},
			"bad-size-zero":                           {"section": "11.1", "says": "no file can show a disagreement at size 0"},
			"bad-one-past-the-cap":                    {"section": "11.1", "says": "MAX_EVIDENCE_BYTES"},
			"bad-size-above-held":                     {"section": "11.1", "says": "not above `held`'s own size"},
			"bad-bool-size":                           {"section": "11.1", "says": "the `size` field is a boolean rather than a uint"},
			"bad-policy-says-quorum-none":             {"section": "11.1", "says": "never the one in the file"},
			"bad-policy-unparseable":                  {"section": "11.1", "says": "MUST parse as `c2sp.org/tlog-policy`"},
			"bad-policy-unparseable-and-foreign-held": {"section": "11.1", "says": "MUST parse as `c2sp.org/tlog-policy`"},
			"bad-proof-at-same-size":                  {"section": "11.1", "says": "Empty when `size` equals"},
			"bad-consistent":                          {"section": "11.1", "says": "only if `held_root` differs"},
			"bad-other-origin":                        {"section": "11.1", "says": "this network's origin"},
			"bad-forged-proof":                        {"section": "11.1", "says": "check `proof` chains"},
			"bad-unverifiable-conflicting":            {"section": "11.1", "says": "verify **both** checkpoints"},
			"bad-size-mismatch":                       {"section": "11.1", "says": "`conflicting`'s size equals `size`"},
		},
		"cases": forkCases,
		"codes": forkCodes,
		// Cold gate run 12: the files that MUST prove a fork, named so a
		// reader is held to the positives as well as the negatives.
		"sound": []string{"evidence-at-same-size", "evidence", "policy-not-the-readers", "evidence-at-64", "evidence-at-the-cap"},
		"comment": "evidence that MUST NOT be acted on, checked against trust.cbor. " +
			"bad-consistent is a log and its own earlier self -- every signature valid, " +
			"both heads cosigned, the roots agreeing. bad-other-origin is a real fork of " +
			"another network, which this anchor has no business accepting. `says` is a " +
			"semantic hint, a phrase the refusal is about; `codes` names the SPEC §11.1 " +
			"code each MUST be refused with, and the code is the contract. " +
			"`policy-not-the-readers.cbor` is not listed here: " +
			"it carries a policy the reader does not share and MUST still prove the fork, " +
			"because the field is informational and the reader's own policy decides",
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(encoded, '\n'), 0o644)
}

// heldHeadBytes is the held tree's own head, as bytes.
func heldHeadBytes(tree *tlog.Tree) []byte {
	head := tree.Head()
	return append([]byte(nil), head[:]...)
}

// sameSizeBranch is a divergent log with the *same* number of entries as the
// one held, so evidence about it needs no consistency proof (§11.1).
func sameSizeBranch(entries [][]byte, divergent []byte) [][]byte {
	branch := append([][]byte(nil), entries[:forkAt]...)
	branch = append(branch, divergent)
	return append(branch, entries[forkAt+1:]...)
}

// policyOf reads the generated trust file's policy, so the evidence carries
// the same text a node would check it against.
func policyOf(root string) string {
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		return ""
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		return ""
	}
	return doc.Policy
}

// hugePolicy is a valid `tlog-policy` far past the evidence size cap. The
// grammar bounds a `witness` URL not at all, which is the only field in the
// whole artifact with room to grow while staying correct.
func hugePolicy(root string) string {
	return policyWithWitnessURL(root, "https://witness.example/"+strings.Repeat("padding/", 9000))
}

// policyWithWitnessURL is the fixture's log line and first witness, with that
// witness given `url`, and a quorum of it. A witness URL is the one field the
// policy grammar does not bound, which is what makes it the place to pad.
func policyWithWitnessURL(root, url string) string {
	var logLine, witnessLine string
	for _, line := range strings.Split(policyOf(root), "\n") {
		switch {
		case strings.HasPrefix(line, "log "):
			logLine = line
		case strings.HasPrefix(line, "witness ") && witnessLine == "":
			witnessLine = line
		}
	}
	fields := strings.Fields(witnessLine)
	name, vkey := fields[1], fields[2]
	return logLine + "\nwitness " + name + " " + vkey + " " + url +
		"\nquorum " + name + "\n"
}

// evidenceOfSize is `sound` -- valid evidence of a real fork -- with its
// carried policy padded until the encoded file is exactly `target` bytes. The
// carried policy decides nothing (§11.1), so the padding changes the size and
// nothing else: the file proves the fork, or is refused for its size alone.
func evidenceOfSize(root string, sound *forkevidence.Evidence, target int) ([]byte, error) {
	pad := 100
	for range 8 {
		ev := *sound
		ev.Policy = policyWithWitnessURL(root, "https://witness.example/"+strings.Repeat("p", pad))
		raw, err := ev.Encode()
		if err != nil {
			return nil, err
		}
		if len(raw) == target {
			return raw, nil
		}
		pad += target - len(raw)
		if pad < 1 {
			return nil, fmt.Errorf("evidence is already more than %d bytes", target)
		}
	}
	return nil, fmt.Errorf("cannot pad evidence to exactly %d bytes", target)
}

// quorumNonePolicy is a policy an accuser might write to make its own evidence
// check out: valid, parseable, and satisfied by no cosignatures at all.
func quorumNonePolicy(root string) string {
	for _, line := range strings.Split(policyOf(root), "\n") {
		if strings.HasPrefix(line, "log ") {
			return line + "\nquorum none\n"
		}
	}
	return ""
}

// unmeetablePolicy is a valid `tlog-policy` that these checkpoints do NOT
// satisfy: it requires a witness that cosigned nothing. A reader verifying
// under the carried field would refuse sound evidence and skip the alarm §11
// rule 1 requires, so this is the positive half of the rule.
func unmeetablePolicy(root string, ghost ed25519.PrivateKey) string {
	var logLine string
	for _, line := range strings.Split(policyOf(root), "\n") {
		if strings.HasPrefix(line, "log ") {
			logLine = line
		}
	}
	vkey := note.CosignerVerifierKey("norn-witness/ghost", ghost.Public().(ed25519.PublicKey))
	return logLine + "\nwitness ghost " + vkey + "\nquorum ghost\n"
}
