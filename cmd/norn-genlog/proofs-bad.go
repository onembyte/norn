// These vectors write proofs-bad and the proof size boundary in proofs.

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
	upstream "golang.org/x/mod/sumdb/tlog"
)

// writeBadProofs ships §8's refusals of a bundle. Each differs from a valid
// bundle in exactly one thing, so a verifier that skips one check accepts one
// file -- except the one built to differ in two, which exists to pin §10.1's
// order between them.
func writeBadProofs(root, origin string, key ed25519.PrivateKey, entries [][]byte,
	signed string, signers []cosignpkg.Signer, device string, index int64,
	inclusion upstream.RecordProof) error {

	dir := filepath.Join(root, "proofs-bad")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	write := func(name string, b *proof.Bundle) error {
		raw, err := b.Encode()
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, name+".bundle"), raw, 0o644)
	}

	// 1. The proof is for this index; the entry is a different one.
	other := int64(0)
	if index == 0 {
		other = 1
	}
	wrongEntry, err := proof.Build(device, index, entries[other], inclusion, signed)
	if err != nil {
		return err
	}
	if err := write("wrong-entry", wrongEntry); err != nil {
		return err
	}

	// 2. A checkpoint from another network: valid, and about a different log.
	elsewhere, err := signedHeadOver(root, "norn/elsewhere", key, entries, signers)
	if err != nil {
		return err
	}
	foreign, err := proof.Build(device, index, entries[index], inclusion, elsewhere)
	if err != nil {
		return err
	}
	if err := write("foreign-checkpoint", foreign); err != nil {
		return err
	}

	// 3. One hash of the inclusion path altered. Everything else is right,
	// which is the only construction that separates checking the path from
	// carrying it.
	tampered := append(upstream.RecordProof(nil), inclusion...)
	if len(tampered) == 0 {
		return fmt.Errorf("the first device's inclusion proof is empty; pick another")
	}
	tampered[0][0] ^= 0x01
	tamperedBundle, err := proof.Build(device, index, entries[index], tampered, signed)
	if err != nil {
		return err
	}
	if err := write("tampered-proof", tamperedBundle); err != nil {
		return err
	}

	// 4. The right tree, signed by a key the anchor does not name.
	stranger, err := seedKey(root, "stranger")
	if err != nil {
		return err
	}
	strangerHead, err := signedHeadOver(root, origin, stranger, entries, signers)
	if err != nil {
		return err
	}
	wrongKey, err := proof.Build(device, index, entries[index], inclusion, strangerHead)
	if err != nil {
		return err
	}
	if err := write("wrong-log-key", wrongKey); err != nil {
		return err
	}

	// J3: §8 sells a bundle as checkable by somebody holding only the trust
	// file, and §8.1 asked only for the log signature. A checkpoint with no
	// witness corroboration, or one for another network, is exactly what a
	// lying log would produce -- and nothing here refused either.
	uncosigned, err := note.Sign(mustBody(signed), origin, key)
	if err != nil {
		return err
	}
	noQuorum, err := proof.Build(device, index, entries[index], inclusion, uncosigned)
	if err != nil {
		return err
	}
	if err := write("no-quorum", noQuorum); err != nil {
		return err
	}

	// 6.5l-vi-b-ii-e. Two faults: nobody cosigned, and the inclusion path is
	// tampered. §10.1 checks the checkpoint before the proof, so this is
	// `quorum`; a reader that checks the proof first refuses it as
	// `inclusion`. D-061 names exactly this pair -- "a bundle's quorum before
	// its inclusion proof" -- as an ordering no file could show.
	noQuorumTampered, err := proof.Build(device, index, entries[index], tampered, uncosigned)
	if err != nil {
		return err
	}
	if err := write("no-quorum-tampered-proof", noQuorumTampered); err != nil {
		return err
	}

	otherOrigin := "norn/elsewhere"
	body := mustBody(signed)
	wrongBody := otherOrigin + body[strings.Index(body, "\n"):]
	wrongHead, err := note.Sign(wrongBody, origin, key)
	if err != nil {
		return err
	}
	wrongHead, err = staggeredCosigner(signers)(wrongHead)
	if err != nil {
		return err
	}
	wrongOrigin, err := proof.Build(device, index, entries[index], inclusion, wrongHead)
	if err != nil {
		return err
	}
	if err := write("wrong-origin", wrongOrigin); err != nil {
		return err
	}

	// Cold gate run 8, D25. §8.1 calls the bundle a closed map of exactly six
	// keys and `device` "the `device_id` this bundle proves"; the schema and
	// the version were enforced and unvectored, and the binding between
	// `device` and the entry was not checked at all.
	honest, err := proof.Build(device, index, entries[index], inclusion, signed)
	if err != nil {
		return err
	}
	raw, err := honest.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "open-schema.bundle"),
		withExtraKey(raw, "surprise", "an unpermitted bundle key"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "wrong-version.bundle"),
		withVersion(raw, 2), 0o644); err != nil {
		return err
	}
	// The proof, the entry and the checkpoint are all honest; only the label
	// beside them is another device's, and the inclusion proof says nothing
	// about a label.
	mislabelled, err := proof.Build("somebody-else", index, entries[index], inclusion, signed)
	if err != nil {
		return err
	}
	if err := write("device-not-in-entry", mislabelled); err != nil {
		return err
	}

	// Cold gate run 12, D20. §8.1 binds `device` to "the `device_id` the
	// `entry` names -- for an `enroll`, the id inside the embedded request;
	// for the other device types, the `device_id` in the body", and every
	// bundle here proved an `enroll`. These prove a `rotate` and a `revoke`,
	// real accepted entries with real inclusion proofs, under another
	// device's label: a reader that binds only enrolments accepts them.
	tree, err := tlog.Build(entries)
	if err != nil {
		return err
	}
	for _, other := range []struct {
		file, kind, subject, label string
	}{
		{"rotate-entry-other-device", "rotate", "nas", "printer"},
		{"revoke-entry-other-device", "revoke", "rootrevoked", "nas"},
	} {
		at := -1
		for i, raw := range entries {
			env, err := entry.Decode(raw)
			if err == nil && env.T == other.kind && env.Body["device_id"] == other.subject {
				at = i
				break
			}
		}
		if at < 0 {
			return fmt.Errorf("the log has no %s entry for %s", other.kind, other.subject)
		}
		p, err := tree.InclusionProof(int64(at))
		if err != nil {
			return err
		}
		b, err := proof.Build(other.label, int64(at), entries[at], p, signed)
		if err != nil {
			return err
		}
		if err := write(other.file, b); err != nil {
			return err
		}
	}

	// Cold gate run 13, D15. An unlisted witness's real cosignatures add
	// bytes without changing any check. These twins isolate the size cap.
	nasRaw, err := os.ReadFile(filepath.Join(root, "proofs", "nas.bundle"))
	if err != nil {
		return err
	}
	nas, err := proof.Decode(nasRaw)
	if err != nil {
		return err
	}
	for _, boundary := range []struct {
		dir, name string
		size      int
	}{
		{"proofs", "at-the-cap", proof.MaxBundleBytes},
		{"proofs-bad", "one-past-the-cap", proof.MaxBundleBytes + 1},
	} {
		raw, err := bundleOfSize(root, nas, boundary.size)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, boundary.dir, boundary.name+".bundle"), raw, 0o644); err != nil {
			return err
		}
	}

	// Every negative names the section that states its rule (run 10).
	bundleRules := map[string]map[string]string{
		"one-past-the-cap":          {"section": "8.1", "says": "larger than this MUST be refused on length"},
		"open-schema":               {"section": "8.1", "says": "a closed map of exactly these six keys"},
		"wrong-version":             {"section": "8.1", "says": "`v` | uint | `1`"},
		"device-not-in-entry":       {"section": "8.1", "says": "`device` is the `device_id` the `entry` names"},
		"rotate-entry-other-device": {"section": "8.1", "says": "`device` is the `device_id` the `entry` names"},
		"revoke-entry-other-device": {"section": "8.1", "says": "`device` is the `device_id` the `entry` names"},
		"no-quorum":                 {"section": "8.1", "says": "a satisfied witness quorum"},
		"no-quorum-tampered-proof":  {"section": "8.1", "says": "a satisfied witness quorum"},
		"wrong-origin":              {"section": "8.1", "says": "this network's origin"},
		"wrong-entry":               {"section": "8.1", "says": "reach that checkpoint's root at `index`"},
		"foreign-checkpoint":        {"section": "8.1", "says": "under the log keys the verifier trusts"},
		"tampered-proof":            {"section": "8.1", "says": "reach that checkpoint's root at `index`"},
		"wrong-log-key":             {"section": "8.1", "says": "under the log keys the verifier trusts"},
	}

	// D-061: the §10.1 code each is refused with, in the bundle table's
	// order. Three files fail two steps and are coded with the earlier:
	// foreign-checkpoint (signed under another origin's name: the
	// signature, then the origin), wrong-entry (the inclusion proof, then
	// the binding -- the entry is another one's), and
	// no-quorum-tampered-proof (the quorum, then the inclusion proof).
	bundleCodes := map[string]refusal.Code{
		"one-past-the-cap":          refusal.Bundle,
		"open-schema":               refusal.Bundle,
		"wrong-version":             refusal.Bundle,
		"device-not-in-entry":       refusal.Binding,
		"rotate-entry-other-device": refusal.Binding,
		"revoke-entry-other-device": refusal.Binding,
		"no-quorum":                 refusal.Quorum,
		"no-quorum-tampered-proof":  refusal.Quorum,
		"wrong-origin":              refusal.Origin,
		"wrong-entry":               refusal.Inclusion,
		"foreign-checkpoint":        refusal.LogSignature,
		"tampered-proof":            refusal.Inclusion,
		"wrong-log-key":             refusal.LogSignature,
	}
	bundleCases := []map[string]string{
		{"name": "one-past-the-cap", "says": "input exceeds"},
		{"name": "open-schema", "says": "unknown field"},
		{"name": "wrong-version", "says": "unsupported version"},
		{"name": "device-not-in-entry", "says": "carries an entry about"},
		{"name": "rotate-entry-other-device", "says": "carries an entry about"},
		{"name": "revoke-entry-other-device", "says": "carries an entry about"},
		{"name": "no-quorum", "says": "no quorum cosigned"},
		{"name": "no-quorum-tampered-proof", "says": "no quorum cosigned"},
		{"name": "wrong-origin", "says": "is for origin"},
		{"name": "wrong-entry", "says": "inclusion proof"},
		{"name": "foreign-checkpoint", "says": "no valid signature from a trusted key"},
		{"name": "tampered-proof", "says": "inclusion proof"},
		{"name": "wrong-log-key", "says": "no valid signature from a trusted key"},
	}
	if err := checkCodes("proofs-bad", namesOf(bundleCases), bundleCodes, refusal.Known); err != nil {
		return err
	}

	meta := map[string]any{
		"log_key": note.VerifierKey(origin, key.Public().(ed25519.PublicKey)),
		"origin":  origin,
		"rules":   bundleRules,
		"cases":   bundleCases,
		"codes":   bundleCodes,
		"comment": "bundles that MUST be refused under the log key above, with the SPEC " +
			"§10.1 code `codes` names for each. Each differs from a valid bundle in " +
			"exactly one thing, so a verifier that skips one check accepts exactly one " +
			"of them -- except no-quorum-tampered-proof, which differs in two so that " +
			"§10.1's order decides: it is `quorum`, and a reader that checks the " +
			"inclusion proof first says `inclusion`",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

// bundleOfSize grows only the checkpoint's signature block. Repeated real
// stranger lines supply most of the bytes; a final unlisted name supplies
// the remainder, including any change in the CBOR text-length header.
func bundleOfSize(root string, base *proof.Bundle, target int) ([]byte, error) {
	key, err := seedKey(root, "stranger")
	if err != nil {
		return nil, err
	}
	body, _, err := note.Split(base.Checkpoint)
	if err != nil {
		return nil, err
	}
	const name = "norn-witness/stranger"
	line, err := cosignpkg.Sign(body, name, key, time.Unix(CosignedAt, 0))
	if err != nil {
		return nil, err
	}
	raw, err := base.Encode()
	if err != nil {
		return nil, err
	}
	// Leave room for the final line and a wider CBOR length header.
	count := (target - len(raw) - 2*len(line)) / (len(line) + 1)
	if count < 0 {
		return nil, fmt.Errorf("bundle target %d is too small", target)
	}
	prefix := base.Checkpoint + strings.Repeat(line+"\n", count)
	b := *base
	b.Checkpoint = prefix + line + "\n"
	raw, err = b.Encode()
	if err != nil {
		return nil, err
	}
	if len(raw) > target {
		return nil, fmt.Errorf("bundle already exceeds target %d", target)
	}
	final, err := cosignpkg.Sign(body, name+strings.Repeat("x", target-len(raw)), key, time.Unix(CosignedAt, 0))
	if err != nil {
		return nil, err
	}
	b.Checkpoint = prefix + final + "\n"
	raw, err = b.Encode()
	if err != nil {
		return nil, err
	}
	if len(raw) != target {
		return nil, fmt.Errorf("bundle is %d bytes, want %d", len(raw), target)
	}
	return raw, nil
}
