// Command norn-genlog writes the served-log vectors: a real tlog-tiles
// directory built from the fixture's entries, a signed checkpoint, and a proof
// bundle per active device.
//
// These vectors have a different provenance from the rest of the suite, and
// SPEC §12 says so: the entry and state vectors come from the Python reference
// and the Go code must match them, while these come from the Go code and are
// validated by upstream libraries -- transparency-dev/formats parses the
// checkpoint, x/mod checks the proofs. Nothing here is checked only against
// its own author.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/onembyte/norn/internal/cbor"
	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
	upstream "golang.org/x/mod/sumdb/tlog"
	"time"
)

// logKey is the key the shipped `trust.cbor` names as this network's log key.
//
// It is read from `keys.json` rather than invented here, and that is the whole
// point: the suite has two provenances (§12), and until 2.9g the Go half signed
// its checkpoints with a seed of its own while the reference half's trust file
// named a different key. Nothing noticed, because no verifier checked a
// checkpoint signature until 2.9e-i. A suite whose two halves disagree is a
// suite that cannot be followed.
// seedKey reads one test key out of keys.json.
func seedKey(root, name string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(root, "keys.json"))
	if err != nil {
		return nil, err
	}
	var keys struct {
		Ed25519 map[string]struct {
			Seed string `json:"seed"`
		} `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(keys.Ed25519[name].Seed)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("keys.json has no usable %s seed", name)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// WitnessNames are the fixture's witnesses, in the order the policy lists them.
var WitnessNames = []string{"pi", "vps", "friend"}

// CosignSpread is how much later each witness answers than the one before it.
// Until cold gate run 6 all three cosigned at the same instant, so the newest
// timestamp, the median and the k-th newest agreed and no vector said which
// §5.3 means. They answer seven seconds apart now, which makes the 2-of-3
// quorum time the *second* newest and tells the three readings apart.
const CosignSpread = 7

// CosignedAt is the fixed instant the fixture's witnesses cosign at.
//
// Fixed, because a vector whose bytes changed with the clock could not be
// compared to anything. Witness time is the clock elsewhere (GOSSIP.md part
// 5); here it is a number the suite agrees on.
const CosignedAt = 1_760_003_600

// witnessSigners loads the fixture's witnesses in the order the policy lists
// them, so the cosignature lines land in a fixed order and the fixture stays
// byte-reproducible.
// staggeredCosigner appends each witness's line at its own instant, in policy
// order, by chaining one single-signer `Append` per witness.
func staggeredCosigner(signers []cosignpkg.Signer) func(string) (string, error) {
	return func(signed string) (string, error) {
		out := signed
		for i, s := range signers {
			at := time.Unix(CosignedAt+int64(i*CosignSpread), 0)
			next, err := cosignpkg.Append([]cosignpkg.Signer{s}, cosignpkg.At(at))(out)
			if err != nil {
				return "", err
			}
			out = next
		}
		return out, nil
	}
}

// QuorumTimeOf is the instant §5.3 derives from a set of cosignature
// timestamps under a k-of-n quorum: the newest instant at which k of them have
// answered. Computed here so the suite can record it for a second implementer.
func QuorumTimeOf(threshold int) int64 {
	// Witness i answers at CosignedAt + i*spread, so the k-th newest of n is
	// the one at index n-k.
	return CosignedAt + int64((len(WitnessNames)-threshold)*CosignSpread)
}

func witnessSigners(root string) ([]cosignpkg.Signer, error) {
	signers := make([]cosignpkg.Signer, 0, len(WitnessNames))
	for _, name := range WitnessNames {
		key, err := seedKey(root, "witness-"+name)
		if err != nil {
			return nil, err
		}
		signers = append(signers, cosignpkg.Signer{Name: "norn-witness/" + name, Key: key})
	}
	return signers, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: norn-genlog <vector root>")
		os.Exit(2)
	}
	root := os.Args[1]
	if err := run(root); err != nil {
		fmt.Fprintln(os.Stderr, "norn-genlog:", err)
		os.Exit(1)
	}
}

func run(root string) error {
	anchor, entries, origin, err := loadFixture(root)
	if err != nil {
		return err
	}

	served := filepath.Join(root, "served")
	if err := os.RemoveAll(served); err != nil {
		return err
	}
	key, err := seedKey(root, "logkey")
	if err != nil {
		return err
	}
	// The fixture's witnesses cosign every head this store publishes, at a
	// fixed instant so a regenerated fixture is byte-identical (§6).
	signers, err := witnessSigners(root)
	if err != nil {
		return err
	}
	store, err := tlogstore.Open(served, origin, key, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(staggeredCosigner(signers))))
	if err != nil {
		return err
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			return err
		}
	}

	// `checkpoint` is the signed note itself, written by the store as it
	// appends (§6). There is no unsigned sibling: a file a verifier is not
	// allowed to believe should not exist where one might read it by mistake.
	// The proof bundles quote it, so read back exactly what is served.
	signed, err := store.SignedCheckpoint()
	if err != nil {
		return err
	}

	// §12.1 owed a fork-evidence vector from Phase 4. Without one, a second
	// implementation has nothing to check its evidence reader against -- and
	// evidence is the artifact `GOSSIP.md` sends to witness operators and blog
	// posts, so it is the last thing that should only ever have been produced
	// by the implementation that reads it.
	if err := writeForkEvidence(root, origin, key, entries, signed, store); err != nil {
		return err
	}

	// The note layer's negatives (G2). Built from the same body the store
	// signed, so they differ from the served checkpoint in exactly one thing.
	if err := writeBadCheckpoints(root, origin, key, signed, signers); err != nil {
		return err
	}

	st := replay.Replay(anchor, entries)
	bundles := filepath.Join(root, "proofs")
	if err := os.RemoveAll(bundles); err != nil {
		return err
	}
	if err := os.MkdirAll(bundles, 0o755); err != nil {
		return err
	}

	ids := make([]string, 0, len(st.Devices))
	for id, d := range st.Devices {
		if d.Status == state.StatusActive {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	for _, id := range ids {
		index := int64(st.Devices[id].SinceIndex)
		p, err := store.InclusionProof(index)
		if err != nil {
			return fmt.Errorf("proof for %s: %w", id, err)
		}
		bundle, err := proof.Build(id, index, entries[index], p, signed)
		if err != nil {
			return err
		}
		raw, err := bundle.Encode()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(bundles, id+".bundle"), raw, 0o644); err != nil {
			return err
		}
	}

	// Cold gate run 11, D14. §8.1's condition 3 read "active with that wg_pk",
	// with no antecedent for "that". Each bundle proves the entry that made
	// its device active, and `rotate` leaves `since_index` alone, so for a
	// device that has rotated the bundle's entry carries a key the device no
	// longer uses. Read strictly, that condition drops every rotated peer. No
	// file joined a bundle to the key a node installs, so both readings
	// passed. This does: the replayed key, beside the bundle that proves the
	// device, and for `nas` the two differ.
	installs := make(map[string]string, len(ids))
	for _, id := range ids {
		installs[id] = st.Devices[id].WgPk
	}

	meta := map[string]any{
		"comment": "the served log and its proof bundles, produced by the Go " +
			"implementation and validated by upstream libraries; see SPEC 12. " +
			"`installs` is the wg_pk, in hex, that a node installs for each device " +
			"once its bundle checks out: the key replay gives (SPEC 8.1 condition 3), " +
			"which is not always the key in the bundle's entry. `nas` rotated after " +
			"it enrolled, so its bundle proves the enrol and names the old key",
		"installs": installs,
		"origin":   origin,
		// Named rather than repeated: the seed lives in keys.json, and a
		// second copy here is a second thing to keep in step.
		"log_key": "keys.json ed25519.logkey — the key trust.cbor names",
		"size":    store.Size(),
		"devices": ids,
		"right_edge_inclusion": map[string]any{
			"file": "right-edge.json", "size": 127, "index": 126,
		},
		// §5.3's evaluation time is derived under the policy that accepted this
		// checkpoint: the shipped trust policy is 2-of-3. The checkpoint also
		// replays a 3-of-3 policy; record that alternate calculation so the
		// vector distinguishes it from a retroactive policy change.
		"checkpoint_quorum_time":      QuorumTimeOf(2),
		"replayed_policy_quorum_time": QuorumTimeOf(3),
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(bundles, "cases.json"), append(blob, '\n'), 0o644); err != nil {
		return err
	}
	if err := writeRightEdgeProof(bundles, entries); err != nil {
		return err
	}
	// §12.1 named four proof refusals and two served-log refusals and shipped
	// none of them (G7). They are the same kind of gap as the note layer's:
	// checked by this project's own tests, and invisible to anybody who
	// receives only the suite.
	first := ids[0]
	firstIndex := int64(st.Devices[first].SinceIndex)
	firstProof, err := store.InclusionProof(firstIndex)
	if err != nil {
		return err
	}
	if err := writeBadProofs(root, origin, key, entries, signed, signers,
		first, firstIndex, firstProof); err != nil {
		return err
	}
	largeServed := filepath.Join(root, "served-large")
	if err := writeServedLarge(root, origin, anchor.Net, entries, key, signers); err != nil {
		return err
	}
	if err := writeBadServed(root, largeServed, 300); err != nil {
		return err
	}
	if err := writeRotatedHead(root, origin, signed, st, signers); err != nil {
		return err
	}
	if err := writeExtraWitnessHead(root, signed, signers); err != nil {
		return err
	}
	if err := writeNameCollisionHead(root, signed, signers); err != nil {
		return err
	}
	if err := writeTwiceCosignedHead(root, signed, signers); err != nil {
		return err
	}
	if err := writeSupersededHead(root, origin, signed, key, signers); err != nil {
		return err
	}
	if err := writeDetectCases(root, origin, key, entries, signed, signers); err != nil {
		return err
	}

	fmt.Printf("served %d entries to %s, %d proof bundles\n", store.Size(), served, len(ids))
	return nil
}

// writeServedLarge exercises the real paths a log reaches after one tile.
// The ordinary replay fixture is intentionally compact; append unique signed
// note entries to a copy so the generated head crosses both tile boundaries
// without changing the protocol state exercised by the other vectors.
func writeServedLarge(root, origin string, net []byte, entries [][]byte,
	logKey ed25519.PrivateKey, signers []cosignpkg.Signer) error {
	const size = 300
	if len(entries) > size {
		return fmt.Errorf("the replay fixture has %d entries, more than the scale log", len(entries))
	}
	scaleEntries := append([][]byte(nil), entries...)
	signerKey, err := seedKey(root, "signer1")
	if err != nil {
		return err
	}
	for index := len(scaleEntries); index < size; index++ {
		after := uint64(index)
		env := &entry.Envelope{
			V: entry.Version, T: "note", Net: append([]byte(nil), net...),
			TS: uint64(CosignedAt + int64(index)), After: &after,
			Body: map[string]any{"text": fmt.Sprintf("multi-tile scale entry %03d", index)},
		}
		if err := entry.Sign(env, signerKey, "signer"); err != nil {
			return fmt.Errorf("sign scale entry %d: %w", index, err)
		}
		raw, err := entry.Encode(env)
		if err != nil {
			return fmt.Errorf("encode scale entry %d: %w", index, err)
		}
		scaleEntries = append(scaleEntries, raw)
	}

	dir := filepath.Join(root, "served-large")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	store, err := tlogstore.Open(dir, origin, logKey, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(staggeredCosigner(signers))))
	if err != nil {
		return err
	}
	for index, raw := range scaleEntries {
		if _, err := store.Append(raw); err != nil {
			return fmt.Errorf("append scale entry %d: %w", index, err)
		}
	}

	tree, err := tlog.Build(scaleEntries)
	if err != nil {
		return err
	}
	tiles, err := tree.Tiles()
	if err != nil {
		return err
	}
	type tileCase struct {
		Path  string `json:"path"`
		Width int    `json:"width"`
	}
	listed := make([]tileCase, 0, len(tiles))
	for _, tile := range tiles {
		listed = append(listed, tileCase{Path: tile.Path(), Width: tile.Width})
	}
	meta := map[string]any{
		"size":  size,
		"tiles": listed,
		"comment": "a 300-entry, signed and cosigned served log. It exercises a full " +
			"level-0 tile, a partial level-0 tile, and the level-1 tile; every listed " +
			"path and width is implied by the checkpoint",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

// writeRightEdgeProof records the RFC 6962 shape D13b found missing: the last
// leaf of a 127-entry tree, where a parity-only inclusion reader answers
// differently. The entry, root and proof are all shipped so a second reader
// can check the path without rebuilding this generator's tree.
func writeRightEdgeProof(dir string, entries [][]byte) error {
	const size, index = 127, 126
	if len(entries) < size {
		return fmt.Errorf("right-edge proof needs %d entries, fixture has %d", size, len(entries))
	}
	tree, err := tlog.Build(entries[:size])
	if err != nil {
		return err
	}
	proof, err := tree.InclusionProof(index)
	if err != nil {
		return err
	}
	leaf := tlog.LeafHash(entries[index])
	head := tree.Head()
	if err := upstream.CheckRecord(proof, size, head, index, leaf); err != nil {
		return fmt.Errorf("generated right-edge proof does not verify: %w", err)
	}
	proofHex := make([]string, len(proof))
	for i, hash := range proof {
		proofHex[i] = hex.EncodeToString(hash[:])
	}
	doc := map[string]any{
		"comment":   "right-edge inclusion proof for the last leaf of a 127-entry tree (D13b)",
		"size":      size,
		"index":     index,
		"entry_b64": base64.StdEncoding.EncodeToString(entries[index]),
		"leaf_hash": hex.EncodeToString(leaf[:]),
		"root":      hex.EncodeToString(head[:]),
		"proof":     proofHex,
	}
	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "right-edge.json"), append(blob, '\n'), 0o644)
}

// writeRotatedHead ships §9.4's rotation case: the same head, signed by a key
// the log's roots published rather than by the one the trust file names.
//
// It is the only vector with two correct answers, and which one is right
// depends on what the reader has done rather than on what the file contains: a
// node holding only `trust.cbor` must refuse it, and a node that has replayed
// this log -- and so learned the key -- must accept it. That is the whole of
// D-020, and nothing in the suite expressed it.
func writeRotatedHead(root, origin, signed string, st *state.State,
	signers []cosignpkg.Signer) error {

	if len(st.LogKeys) == 0 {
		return fmt.Errorf("the fixture publishes no log_key entry to rotate to")
	}
	raw, err := hex.DecodeString(st.LogKeys[0].Pk)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("the first published log key is not a 32-byte key")
	}
	key, err := seedKeyForPublic(root, raw)
	if err != nil {
		return err
	}

	body, err := noteBody(signed)
	if err != nil {
		return err
	}
	head, err := note.Sign(body, origin, key)
	if err != nil {
		return err
	}
	head, err = staggeredCosigner(signers)(head)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-rotated")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
		return err
	}
	meta := map[string]any{
		"serve_over":  "served",
		"signed_by":   st.LogKeys[0].Pk,
		"since_index": st.LogKeys[0].SinceIndex,
		"overlap":     st.LogKeys[0].Overlap,
		"comment": "the served head, signed by the first log key this log's roots " +
			"published (SPEC 9.4). Serve it in place of served/checkpoint over the same " +
			"tiles. A reader holding only trust.cbor MUST refuse it: it has never seen " +
			"the rotation. A reader that has replayed this log MUST accept it. The two " +
			"answers are both correct, and which applies depends on what the reader has " +
			"done rather than on anything in the file",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

// writeExtraWitnessHead ships §10's rule for a line the reader does not know.
//
// Cold gate run 9, D17: §10 says every line naming a witness the policy lists
// must verify, and nothing at all about a line naming a key the reader has
// never heard of. `07-unnamed-witness-only` is refused either way -- for want
// of a quorum -- so the suite could not separate "ignore it" from "refuse over
// it", and a reader that refuses stops accepting checkpoints everybody else
// accepts the moment a witness cosigns a log its policy does not list. That is
// normal in a shared log.
func writeExtraWitnessHead(root, signed string, signers []cosignpkg.Signer) error {
	stranger, err := seedKey(root, "stranger")
	if err != nil {
		return err
	}
	const name = "norn-witness/stranger"
	head, err := cosignpkg.Append([]cosignpkg.Signer{{Name: name, Key: stranger}},
		cosignpkg.At(time.Unix(CosignedAt+int64(4*CosignSpread), 0)))(signed)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-extra-witness")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
		return err
	}
	meta := map[string]any{
		"serve_over": "served",
		"stranger":   name,
		"comment": "the served head with one MORE cosignature line, from a witness " +
			"the policy never names and the trust file does not list. It verifies " +
			"under its own key and counts for nothing. SPEC 10: a line naming a " +
			"witness the policy lists must verify; a line naming anyone else is " +
			"IGNORED, not refused -- a witness cosigning a log this node's policy " +
			"does not list is normal in a shared log, and a reader that refuses " +
			"over it stops accepting checkpoints everybody else accepts. This head " +
			"MUST be accepted. Serve it in place of served/checkpoint over the " +
			"same tiles",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

// writeNameCollisionHead ships §10's definition of "a line naming a witness".
//
// Cold gate run 9 settled the easy half -- a line from a name the policy does
// not list is ignored -- and run 10 (D16) found the hard one open: a line
// carrying a *listed* witness's name under somebody else's key. §7 makes the
// key id bind the name, the algorithm and the public key, so such a line names
// nobody and is ignored like any stranger's. The other reading, matching on
// the name alone, hands every party a veto: cosign a head under a name you do
// not hold and every node reading it that way refuses the head, including
// nodes that have never heard of you. `served-extra-witness/` cannot separate
// them, because its stranger uses a different name.
func writeNameCollisionHead(root, signed string, signers []cosignpkg.Signer) error {
	if len(signers) == 0 {
		return fmt.Errorf("no witnesses to collide with")
	}
	// The same key `served-extra-witness/` uses, under a different name. That
	// pairing is §7's point made twice: one key, two names, two key ids, and
	// both lines ignored -- one because the name is unknown, this one because
	// the id is.
	impostor, err := seedKey(root, "stranger")
	if err != nil {
		return err
	}
	// The first witness's NAME, the stranger's KEY. The line verifies under
	// that key and under no key the policy publishes.
	borrowed := signers[0].Name
	head, err := cosignpkg.Append([]cosignpkg.Signer{{Name: borrowed, Key: impostor}},
		cosignpkg.At(time.Unix(CosignedAt+int64(5*CosignSpread), 0)))(signed)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-name-collision")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
		return err
	}
	meta := map[string]any{
		"serve_over": "served",
		"witness":    borrowed,
		"comment": "the served head with one MORE cosignature line, carrying a " +
			"LISTED witness's name under a key the policy does not publish for " +
			"it. SPEC 10: a line names a witness the policy lists when its name " +
			"AND key id both match that witness's verifier key -- so this line " +
			"names nobody and is ignored, exactly like a stranger's. Two lines " +
			"carry the name and one carries the key id. This head MUST be " +
			"accepted; a reader matching on the name alone refuses it, which " +
			"would let anyone deny a head to every node on the network by " +
			"cosigning it under a name they do not hold. Serve it in place of " +
			"served/checkpoint over the same tiles",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

// writeTwiceCosignedHead ships §5.3's tie-break: one witness, two verifying
// cosignature lines, at different times.
//
// Cold gate run 8, D5... D13: §5.3 says "two verifying lines from the same
// witness with different timestamps are its newest", and nothing in the suite
// had two lines from one witness that BOTH verify.
// `checkpoints-bad/12-second-line-from-one-witness` cannot stand in: its
// second line does not verify, so §10's per-line rule refuses the checkpoint
// before the tie-break is reached. `quorum-time-oldest-line` -- a reader that
// reduces each witness to its OLDEST line -- passed all 582 checks.
//
// `pi` answers again three spreads out, so the two readings give different
// answers: newest-per-witness puts pi ahead of both others and the 2-of-3
// instant lands on `friend`; oldest-per-witness leaves pi at the back and it
// lands on `vps`. Every line here verifies, so the checkpoint is valid and the
// only question is which instant it vouches for.
func writeTwiceCosignedHead(root, signed string, signers []cosignpkg.Signer) error {
	if len(signers) < 3 {
		return fmt.Errorf("the fixture has %d witnesses; this case needs three", len(signers))
	}
	again := time.Unix(CosignedAt+int64(3*CosignSpread), 0)
	head, err := cosignpkg.Append([]cosignpkg.Signer{signers[0]}, cosignpkg.At(again))(signed)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-twice-cosigned")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
		return err
	}
	meta := map[string]any{
		"serve_over":   "served",
		"signs_twice":  signers[0].Name,
		"quorum_time":  CosignedAt + int64(2*CosignSpread),
		"oldest_would": CosignedAt + int64(CosignSpread),
		"comment": "the served head with a FOURTH cosignature line: " +
			signers[0].Name + " answers a second time, later, and both of its lines " +
			"verify. SPEC 5.3 says a witness counts once, at its newest, so this head " +
			"MUST be accepted and its evaluation time is `quorum_time`. A reader that " +
			"takes each witness's oldest line instead gets `oldest_would`, which is " +
			"the reading this case exists to rule out. Serve it in place of " +
			"served/checkpoint over the same tiles",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

// writeSupersededHead ships §9.4's policy case: the served head cosigned by
// exactly two witnesses.
//
// The fixture's roots raise the quorum from two of three to three of three, so
// this head satisfies the trust file's policy and not the one the log
// publishes. Like `served-rotated/` it has two correct answers, and this time
// the informed reader is the stricter one: raising a quorum has to bind the
// nodes that were already watching, or it protects only the ones who were not.
func writeSupersededHead(root, origin, signed string, key ed25519.PrivateKey,
	signers []cosignpkg.Signer) error {

	if len(signers) < 3 {
		return fmt.Errorf("the fixture has %d witnesses; this case needs three", len(signers))
	}
	body, err := noteBody(signed)
	if err != nil {
		return err
	}
	head, err := note.Sign(body, origin, key)
	if err != nil {
		return err
	}
	head, err = staggeredCosigner(signers[:2])(head)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-superseded")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
		return err
	}
	meta := map[string]any{
		"serve_over":  "served",
		"cosigned_by": []string{signers[0].Name, signers[1].Name},
		"comment": "the served head cosigned by two of the three witnesses. A reader " +
			"holding only trust.cbor requires two and MUST accept it; a reader that has " +
			"replayed this log has seen its roots raise the quorum to three and MUST " +
			"refuse it (SPEC 9.4). Serve it in place of served/checkpoint over the same " +
			"tiles. Two correct answers again, and here the informed reader is the " +
			"stricter one",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

// writeDetectCases ships the sequences §10's stored-checkpoint block needs.
//
// Everything else in the suite is one artifact judged on its own. These are
// *pairs*: what a node already holds, and what it is then offered. Cold gate
// run 7's implementation contained none of §10's stored block, none of §11's
// four duties and no staleness rule, and scored 241/241 -- because nothing in
// the suite was ever a second checkpoint shown to the same reader.
//
// The four outcomes a reader has to tell apart:
//
//   - a larger consistent head: accept it;
//   - a smaller head of the same log: refuse it, and do not call it a fork --
//     an accusation that cannot be proved must not be made;
//   - a different root at the same size: prove a fork;
//   - a *shorter* divergent branch: prove a fork, not a rollback. This is the
//     one a careless reader files under "logs do not shrink", and it is how a
//     forking log would hide.
func writeDetectCases(root, origin string, key ed25519.PrivateKey, entries [][]byte,
	signed string, signers []cosignpkg.Signer) error {

	dir := filepath.Join(root, "detect")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	divergent, err := forkEntry(root)
	if err != nil {
		return err
	}

	// An honest earlier view of this same log, served with its own tiles.
	honest, err := serveInto(filepath.Join(dir, "honest-earlier"), origin, key,
		entries[:forkAt], signers)
	if err != nil {
		return err
	}
	// A branch that diverges at the same size as that earlier view.
	sameSize := append(append([][]byte(nil), entries[:forkAt-1]...), divergent)
	if _, err := serveInto(filepath.Join(dir, "fork-same-size"), origin, key,
		sameSize, signers); err != nil {
		return err
	}
	// A branch that diverges and is *shorter* than the full log: the case a
	// careless reader files under "logs do not shrink".
	shorter := append(append([][]byte(nil), entries[:forkAt]...), divergent)
	if _, err := serveInto(filepath.Join(dir, "fork-shorter"), origin, key,
		shorter, signers); err != nil {
		return err
	}

	// Cold gate run 12, D4. A branch that diverges below the stored size and
	// then grows past it: the most ordinary equivocation there is, and the
	// shape detect/ did not have. A reader that compares the branches only
	// when the served head is the same size or shorter accepts it.
	longer := append(append([][]byte(nil), entries[:forkAt-1]...), divergent)
	longer = append(longer, entries[forkAt:forkAt+20]...)
	if _, err := serveInto(filepath.Join(dir, "fork-longer"), origin, key,
		longer, signers); err != nil {
		return err
	}
	// Cold gate run 12, D5. This log, honestly signed, with one byte of one
	// entry changed in transit. Its entries do not hash to its head (§10.1
	// step 9, `head`) and, recomputed at the stored size, they disagree with
	// the stored head too -- so a reader that compares branches before it
	// checks the head accuses an honest log of forking, permanently.
	if _, err := serveInto(filepath.Join(dir, "tampered-current"), origin, key,
		entries, signers); err != nil {
		return err
	}
	bundle := filepath.Join(dir, "tampered-current",
		filepath.FromSlash(tlog.EntryBundlePath(0, len(entries)%tlog.TileWidth)))
	tampered, err := os.ReadFile(bundle)
	if err != nil {
		return err
	}
	tampered[len(tampered)-1] ^= 0x01
	if err := os.WriteFile(bundle, tampered, 0o644); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, "earlier.checkpoint"),
		[]byte(honest), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "current.checkpoint"),
		[]byte(signed), 0o644); err != nil {
		return err
	}

	// §8.1's condition 4: the staleness ladder. `params.staleness` travels all
	// the way into `state.json` and, until this file, was read by nothing.
	// `elapsed` is monotonic time since the quorum time was learned (§5.3), so
	// these cases are a table over a pure function and need no artifacts.
	stale := map[string]any{
		"staleness": 900,
		"hard":      3600,
		"cases": []map[string]any{
			{"name": "fresh", "elapsed": 0, "expect": "fresh"},
			{"name": "at-the-staleness-boundary", "elapsed": 900, "expect": "fresh"},
			{"name": "one-second-past", "elapsed": 901, "expect": "degraded"},
			{"name": "past-hard", "elapsed": 3601, "expect": "hard_stale"},
			{"name": "no-clock", "elapsed": 0, "have_clock": false, "expect": "unknown"},
			// Cold gate run 9, D9. `S_hard` is opt-in, and zero means NOT
			// CONFIGURED -- not "no headroom". Every other case here carries
			// 3600, so a reader that read 0 as a limit of zero passed the whole
			// suite while dropping every peer the moment a view went stale,
			// which is the outcome §8.1's asymmetry exists to prevent.
			{"name": "unconfigured-hard-stays-degraded", "elapsed": 100000,
				"hard": 0, "expect": "degraded"},
			{"name": "unconfigured-hard-still-fresh", "elapsed": 0,
				"hard": 0, "expect": "fresh"},
			// Cold gate run 11, D1 (D-060). Every case above has `hard` 3600
			// ABOVE `staleness` 900, so the region where both `fresh` and
			// `hard_stale` hold was unreachable and `HardBeforeFresh` -- the
			// table read the other way round -- passed all 622 checks. The
			// fixture builds this trap itself: genesis sets `staleness` 600
			// and `log/29-params` raises it to 900, so a node that chose
			// S_hard 700 lands in the overlap with no reconfiguration.
			{"name": "hard-below-staleness", "elapsed": 800,
				"hard": 700, "expect": "hard_stale"},
			{"name": "at-the-hard-boundary", "elapsed": 700,
				"hard": 700, "expect": "fresh"},
		},
		"comment": "SPEC 8.1's ladder as a table: `elapsed` is the " +
			"node's monotonic time since it learned the checkpoint's quorum time, " +
			"`staleness` is the network's own from params, and `hard` is this node's " +
			"local S_hard. The rule is `elapsed > staleness`, so the boundary is still " +
			"fresh. A node with no corroborated instant has no clock and reports " +
			"`unknown` rather than guessing. A case may carry its own `hard`, " +
			"overriding the top-level one: zero means S_hard is NOT CONFIGURED, " +
			"not a limit of zero, so such a node stays `degraded` however old the " +
			"view gets rather than dropping every peer. The states are tested in " +
			"SPEC 8.1's order and the first that holds is the answer: `hard_stale` " +
			"comes BEFORE `fresh`, so a node whose own S_hard is tighter than the " +
			"network's staleness goes hard-stale at its own limit -- see " +
			"`hard-below-staleness`, which is the only case separating the two " +
			"readings of the table",
	}
	staleBlob, err := json.MarshalIndent(stale, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "staleness.json"),
		append(staleBlob, '\n'), 0o644); err != nil {
		return err
	}

	meta := map[string]any{
		"cases": []map[string]string{
			{"name": "accept-grown", "stored": "earlier.checkpoint", "serve": "../served",
				"outcome": "accept", "says": "a head that grows on the one this node holds"},
			{"name": "refuse-shrunk", "stored": "current.checkpoint", "serve": "honest-earlier",
				"outcome": "refuse", "says": "a log does not shrink"},
			{"name": "fork-at-the-same-size", "stored": "earlier.checkpoint",
				"serve": "fork-same-size", "outcome": "fork",
				"says": "two roots at one size"},
			{"name": "fork-on-a-shorter-branch", "stored": "current.checkpoint",
				"serve": "fork-shorter", "outcome": "fork",
				"says": "shorter and divergent is a fork, not a rollback"},
			// Cold gate run 9, D10. §10 says a node that does not hold `at`
			// MUST NOT accuse -- and inside §10's own loop it always holds
			// `at`, because it stores a checkpoint only after replaying to it.
			// The clause is for a reader holding a stored head WITHOUT the
			// branch: a monitor that has been handed a checkpoint, or a node
			// restarted from its stored one. Such a reader cannot tell a fork
			// from a rollback, so it refuses and says so.
			{"name": "shorter-with-no-held-branch", "stored": "current.checkpoint",
				"serve": "fork-shorter", "outcome": "refuse", "held": "none",
				"says": "a log does not shrink"},
			{"name": "fork-on-a-longer-branch", "stored": "earlier.checkpoint",
				"serve": "fork-longer", "outcome": "fork",
				"says": "a grown head is compared at the stored size too"},
			{"name": "tampered-bundle-under-a-stored-head", "stored": "current.checkpoint",
				"serve": "tampered-current", "outcome": "refuse",
				"says": "do not hash to the advertised head"},
		},
		// D-061, §10.1: the code each case that is not accepted is refused
		// with. tampered-bundle-under-a-stored-head is `head`, not `fork`:
		// the head is checked before the branches are compared.
		"codes": map[string]refusal.Code{
			"refuse-shrunk":                       refusal.Rollback,
			"fork-at-the-same-size":               refusal.Fork,
			"fork-on-a-shorter-branch":            refusal.Fork,
			"shorter-with-no-held-branch":         refusal.Rollback,
			"fork-on-a-longer-branch":             refusal.Fork,
			"tampered-bundle-under-a-stored-head": refusal.Head,
		},
		"comment": "pairs, not single artifacts. `stored` is the checkpoint this reader " +
			"already holds, over the entries in `../served`; `serve` is the log it is " +
			"then offered, tiles and all, as a real log would serve it. §10's " +
			"stored-checkpoint block and §11's duties are reached by nothing else here. " +
			"fork-on-a-shorter-branch is the one that matters most: it is what a forking " +
			"log looks like when it hides behind \"logs do not shrink\"",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

// seedKeyForPublic finds the private key in keys.json whose public half is
// this one.
func seedKeyForPublic(root string, public []byte) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(root, "keys.json"))
	if err != nil {
		return nil, err
	}
	var keys struct {
		Ed25519 map[string]struct{ Seed, Public string } `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, err
	}
	want := hex.EncodeToString(public)
	for _, k := range keys.Ed25519 {
		if k.Public != want {
			continue
		}
		seed, err := hex.DecodeString(k.Seed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("keys.json has no usable seed for %s", want)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	return nil, fmt.Errorf("keys.json holds no private key for the published %s", want)
}

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

	// Every negative names the section that states its rule (run 10).
	bundleRules := map[string]map[string]string{
		"open-schema":               {"section": "8.1", "says": "a closed map of exactly these six keys"},
		"wrong-version":             {"section": "8.1", "says": "`v` | uint | `1`"},
		"device-not-in-entry":       {"section": "8.1", "says": "`device` is the `device_id` the `entry` names"},
		"rotate-entry-other-device": {"section": "8.1", "says": "`device` is the `device_id` the `entry` names"},
		"revoke-entry-other-device": {"section": "8.1", "says": "`device` is the `device_id` the `entry` names"},
		"no-quorum":                 {"section": "8.1", "says": "a satisfied witness quorum"},
		"no-quorum-tampered-proof":  {"section": "8.1", "says": "a satisfied witness quorum"},
		"wrong-origin":              {"section": "8.1", "says": "this network's origin"},
		"wrong-entry":               {"section": "8.1", "says": "reach that checkpoint's root at `index`"},
		"foreign-checkpoint":        {"section": "8.1", "says": "this network's log key"},
		"tampered-proof":            {"section": "8.1", "says": "reach that checkpoint's root at `index`"},
		"wrong-log-key":             {"section": "8.1", "says": "this network's log key"},
	}

	// D-061: the §10.1 code each is refused with, in the bundle table's
	// order. Three files fail two steps and are coded with the earlier:
	// foreign-checkpoint (signed under another origin's name: the
	// signature, then the origin), wrong-entry (the inclusion proof, then
	// the binding -- the entry is another one's), and
	// no-quorum-tampered-proof (the quorum, then the inclusion proof).
	bundleCodes := map[string]refusal.Code{
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

// checkCodes refuses to write a manifest whose cases and codes disagree:
// every case names a code on its closed list -- §10.1's for a verifier,
// §11.1's for an evidence reader (D-061) -- and no code names a case that is
// not there. A negative without a code can only say "refused", which a reader
// that runs its checks in the wrong order also says.
func checkCodes[C ~string](dir string, names []string, codes map[string]C, known func(C) bool) error {
	for _, name := range names {
		if code, ok := codes[name]; !ok || !known(code) {
			return fmt.Errorf("%s: case %q names no code on its closed list; every "+
				"negative must say which step refuses it", dir, name)
		}
	}
	if len(codes) != len(names) {
		return fmt.Errorf("%s: %d codes for %d cases", dir, len(codes), len(names))
	}
	return nil
}

// namesOf lists each case's `name`, in order, so a manifest's codes are
// checked against its own cases rather than against a second list of them.
func namesOf[V any](cases []map[string]V) []string {
	out := make([]string, 0, len(cases))
	for _, c := range cases {
		out = append(out, fmt.Sprint(c["name"]))
	}
	return out
}

// leafHashTile turns an entry bundle into the level-0 tile it implies: each
// entry's `H(0x00 ‖ entry)`, concatenated. A served log whose tile is this is
// internally consistent whatever the entries say.
func leafHashTile(bundle []byte) []byte {
	var out []byte
	for len(bundle) >= 2 {
		n := int(bundle[0])<<8 | int(bundle[1])
		if len(bundle) < 2+n {
			return nil
		}
		sum := sha256.Sum256(append([]byte{0x00}, bundle[2:2+n]...))
		out = append(out, sum[:]...)
		bundle = bundle[2+n:]
	}
	return out
}

// writeBadServed ships §6's refusals of a served log. A served log is a
// directory rather than a file, so the case says which path to replace or
// remove.
func writeBadServed(root, served string, size int64) error {
	dir := filepath.Join(root, "served-bad")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	if size <= 0 {
		return fmt.Errorf("cannot build served-bad vectors for an empty log")
	}
	lastBundleIndex := (size - 1) / tlog.TileWidth
	lastBundleWidth := int((size-1)%tlog.TileWidth) + 1
	bundlePath := tlog.EntryBundlePath(lastBundleIndex, lastBundleWidth)
	honest, err := os.ReadFile(filepath.Join(served, filepath.FromSlash(bundlePath)))
	if err != nil {
		return err
	}
	lastEntries, err := tlog.DecodeBundle(honest)
	if err != nil {
		return fmt.Errorf("decode last bundle %s: %w", bundlePath, err)
	}
	if len(lastEntries) != lastBundleWidth {
		return fmt.Errorf("last bundle %s holds %d entries, want %d",
			bundlePath, len(lastEntries), lastBundleWidth)
	}
	tooMany := append(append([][]byte(nil), lastEntries...), lastEntries[len(lastEntries)-1])
	overfull, err := tlog.EncodeBundle(tooMany)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "overfull-entry-bundle.bin"),
		overfull, 0o644); err != nil {
		return err
	}
	// One byte inside an entry, so the bundle still frames correctly and only
	// the leaf hash it produces is wrong.
	tampered := append([]byte(nil), honest...)
	tampered[len(tampered)-1] ^= 0x01
	if err := os.WriteFile(filepath.Join(dir, "tampered-entry-bundle.bin"),
		tampered, 0o644); err != nil {
		return err
	}

	// Cold-model gate run 7, defect J4. Both cases above are *entry bundle*
	// cases, so until this one nothing in the suite ever opened a hash tile
	// and `blind-tiles` -- a verifier that never fetches `tile/0/...` at all
	// -- reproduced the whole manifest. One byte inside one leaf hash leaves
	// the entries and the signed head untouched, so the tile rule of SPEC 6
	// is the only thing that can refuse it.
	tilePath := tlog.TilePath(0, lastBundleIndex, lastBundleWidth)
	honestTile, err := os.ReadFile(filepath.Join(served, filepath.FromSlash(tilePath)))
	if err != nil {
		return err
	}
	badTile := append([]byte(nil), honestTile...)
	badTile[len(badTile)-1] ^= 0x01
	if err := os.WriteFile(filepath.Join(dir, "tampered-hash-tile.bin"),
		badTile, 0o644); err != nil {
		return err
	}

	// Cold-model gate run 10, defect D11. Both tamper cases above CAN be
	// refused by the tile rule alone: changing a byte of an entry changes its
	// leaf hash, so the served tile disagrees and a reader never has to
	// compare the rebuilt head with the checkpoint at all. `V154_NoRebuild`
	// passed all 236 checks on exactly that. (§10.1 checks the head first, so
	// `tampered-entry-bundle` is `head` -- and a tiles-first or tiles-only
	// reader answers `tiles`, which is what makes it the head-before-tiles
	// vector now that cases carry codes.) Here the tile is recomputed over the tampered
	// entries, so the served directory agrees with itself -- and the tree it
	// describes is not the one the checkpoint is signed over. Only "compares
	// its head with the signed checkpoint" can see it.
	consistentTile := leafHashTile(tampered)
	if len(consistentTile) != len(honestTile) {
		return fmt.Errorf("recomputed tile is %d bytes, the served one is %d",
			len(consistentTile), len(honestTile))
	}
	if bytes.Equal(consistentTile, honestTile) {
		return fmt.Errorf("the recomputed tile equals the honest one, so the " +
			"tampered entry did not change its leaf hash")
	}
	if err := os.WriteFile(filepath.Join(dir, "consistent-entry-bundle.bin"),
		tampered, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "consistent-hash-tile.bin"),
		consistentTile, 0o644); err != nil {
		return err
	}

	// D-061: the §10.1 code each is refused with. The head is checked before
	// the tiles, so the tampered bundle -- whose tiles disagree as well -- is
	// `head`.
	servedCodes := map[string]refusal.Code{
		"tampered-entry-bundle":   refusal.Head,
		"missing-entry-bundle":    refusal.Unserved,
		"consistent-tampered-log": refusal.Head,
		"tampered-hash-tile":      refusal.Tiles,
		"overfull-entry-bundle":   refusal.Entries,
	}
	servedCases := []map[string]any{
		{"name": "tampered-entry-bundle", "path": bundlePath,
			"file": "tampered-entry-bundle.bin",
			"says": "one byte of one entry changed: the bundle still frames, and the " +
				"tree it builds is not the one the checkpoint is signed over"},
		{"name": "missing-entry-bundle", "path": bundlePath, "remove": true,
			"says": "a log that will not serve its entries cannot be replayed, and a " +
				"verifier must refuse rather than report what it has"},
		{"name": "consistent-tampered-log", "files": []map[string]string{
			{"path": bundlePath, "file": "consistent-entry-bundle.bin"},
			{"path": tilePath, "file": "consistent-hash-tile.bin"},
		},
			"says": "the entries and the hash tile are tampered *together*, so the " +
				"served log agrees with itself and disagrees with the head the " +
				"checkpoint is signed over: only rebuilding the tree and comparing " +
				"that head can refuse it"},
		{"name": "tampered-hash-tile", "path": tilePath,
			"file": "tampered-hash-tile.bin",
			"says": "one byte of one leaf hash changed: the entries and the signed " +
				"head are untouched, so a verifier that reaches the head without " +
				"opening `tile/0/...` sees nothing wrong, and serves the corrupt " +
				"tile onward to peers asking it for proofs"},
		{"name": "overfull-entry-bundle", "path": bundlePath,
			"file": "overfull-entry-bundle.bin",
			"says": "the bundle decodes but holds one more entry than the checkpoint " +
				"size and its path imply"},
	}
	if err := checkCodes("served-bad", namesOf(servedCases), servedCodes, refusal.Known); err != nil {
		return err
	}

	meta := map[string]any{
		"rules": map[string]map[string]string{
			// 6.5l-vi-b-ii-e: both cited §6's tile sentence. The tampered
			// bundle is refused by the head comparison before any tile is
			// opened, and a missing bundle by §10.1's `unserved`.
			"tampered-entry-bundle":   {"section": "6", "says": "that comparison is what binds the entries to the head"},
			"missing-entry-bundle":    {"section": "10.1", "says": "any file a later step needs and cannot fetch"},
			"tampered-hash-tile":      {"section": "6", "says": "checking them is not optional"},
			"consistent-tampered-log": {"section": "6", "says": "that comparison is what binds the entries to the head"},
			"overfull-entry-bundle":   {"section": "6", "says": "A partial bundle holds **exactly** the number of entries its path declares"},
		},
		"cases":      servedCases,
		"codes":      servedCodes,
		"serve_over": "served-large",
		"comment": "a served log is a directory, so each case names the path to replace " +
			"with `file`, the paths to replace with `files`, or the path to delete " +
			"with `remove`, over an otherwise honest copy of `served-large/`. Every one " +
			"MUST be refused, with the SPEC §10.1 code `codes` names for it",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

func loadFixture(root string) (replay.Anchor, [][]byte, string, error) {
	raw, err := os.ReadFile(filepath.Join(root, "log", "manifest.json"))
	if err != nil {
		return replay.Anchor{}, nil, "", err
	}
	var m struct {
		Anchor struct {
			Net         string `json:"net"`
			GenesisHash string `json:"genesis_hash"`
		} `json:"anchor"`
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return replay.Anchor{}, nil, "", err
	}
	net, err := hex.DecodeString(m.Anchor.Net)
	if err != nil {
		return replay.Anchor{}, nil, "", err
	}
	genesis, err := hex.DecodeString(m.Anchor.GenesisHash)
	if err != nil {
		return replay.Anchor{}, nil, "", err
	}
	entries := make([][]byte, 0, len(m.Entries))
	for _, e := range m.Entries {
		b, err := os.ReadFile(filepath.Join(root, "log", e.Name+".cbor"))
		if err != nil {
			return replay.Anchor{}, nil, "", err
		}
		entries = append(entries, b)
	}

	// The origin is the one the trust file pins, so the served checkpoint is
	// for the same network the entries belong to.
	trustRaw, err := os.ReadFile(filepath.Join(root, "trust.toml"))
	if err != nil {
		return replay.Anchor{}, nil, "", err
	}
	origin := ""
	for _, line := range splitLines(string(trustRaw)) {
		if after, ok := cutPrefix(line, "origin"); ok {
			origin = trimQuoted(after)
			break
		}
	}
	if origin == "" {
		return replay.Anchor{}, nil, "", fmt.Errorf("no origin in trust.toml")
	}
	return replay.Anchor{Net: net, GenesisHash: genesis}, entries, origin, nil
}

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

// withExtraKey re-encodes a CBOR map with one more key, so a closed-schema
// negative differs from a valid artifact in exactly that.
func withExtraKey(raw []byte, key, value string) []byte {
	m := mustMap(raw)
	m[key] = value
	out, err := cbor.Encode(m)
	if err != nil {
		panic(err)
	}
	return out
}

// withVersion re-encodes a CBOR map under another version number.
func withVersion(raw []byte, v uint64) []byte {
	m := mustMap(raw)
	for _, key := range []string{"v", "version"} {
		if _, ok := m[key]; ok {
			m[key] = v
		}
	}
	out, err := cbor.Encode(m)
	if err != nil {
		panic(err)
	}
	return out
}

func mustMap(raw []byte) map[string]any {
	value, err := cbor.Decode(raw)
	if err != nil {
		panic(err)
	}
	m, ok := value.(map[string]any)
	if !ok {
		panic("not a CBOR map")
	}
	return m
}

// mustBody is the note text a signature covers, without the signature lines.
func mustBody(signed string) string {
	i := strings.Index(signed, "\n\n")
	if i < 0 {
		return signed
	}
	return signed[:i+1]
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
			"bad-wrong-version":                       {"section": "11.1", "says": "| `version` | uint | `1` |"},
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
		"sound": []string{"evidence", "policy-not-the-readers", "evidence-at-64", "evidence-at-the-cap"},
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

// serveInto writes a complete tlog-tiles directory over exactly these entries
// and returns its signed head. A branch that is offered to a reader has to
// come with the tiles that back it, exactly as a real log would serve them.
func serveInto(dir, origin string, key ed25519.PrivateKey, entries [][]byte,
	signers []cosignpkg.Signer) (string, error) {

	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	store, err := tlogstore.Open(dir, origin, key, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(staggeredCosigner(signers))))
	if err != nil {
		return "", err
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			return "", err
		}
	}
	return store.SignedCheckpoint()
}

// signedHeadOver builds a cosigned checkpoint over exactly these entries.
func signedHeadOver(root, origin string, key ed25519.PrivateKey,
	entries [][]byte, signers []cosignpkg.Signer) (string, error) {

	dir, err := os.MkdirTemp("", "norn-branch")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	store, err := tlogstore.Open(dir, origin, key, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(staggeredCosigner(signers))))
	if err != nil {
		return "", err
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			return "", err
		}
	}
	return store.SignedCheckpoint()
}

// forkEntry is the entry only the second branch carries: a revoke the real
// network never issued, signed by the fixture's own signers so that every
// signature on the forked branch checks out. That is the difficulty a fork
// presents -- nothing about either head looks wrong on its own.
func forkEntry(root string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		return nil, err
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		return nil, err
	}
	env := &entry.Envelope{
		V: entry.Version, T: "revoke", Net: doc.Net, TS: CosignedAt - 100,
		Body: map[string]any{"device_id": "nas", "reason": "the fork's own idea"},
	}
	for _, name := range []string{"signer1", "signer2"} {
		key, err := seedKey(root, name)
		if err != nil {
			return nil, err
		}
		if err := entry.Sign(env, key, "signer"); err != nil {
			return nil, err
		}
	}
	return entry.Encode(env)
}

// forkAt is where the fixture's second branch diverges: far enough in that the
// two share real history, early enough that the divergence is obvious.
const forkAt = 40

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

// paddedSizeLine re-signs the checkpoint over a body whose size line carries a
// leading zero, so the signature is valid and only the canonical-decimal rule
// can refuse it.
func paddedSizeLine(base, origin string, key ed25519.PrivateKey,
	signers []cosignpkg.Signer) (string, error) {

	body, err := noteBody(base)
	if err != nil {
		return "", err
	}
	lines := strings.SplitN(body, "\n", 3)
	if len(lines) < 3 {
		return "", fmt.Errorf("a checkpoint body has three lines, this has %d", len(lines))
	}
	lines[1] = "0" + lines[1]
	signed, err := note.Sign(strings.Join(lines, "\n"), origin, key)
	if err != nil {
		return "", err
	}
	return staggeredCosigner(signers)(signed)
}

// rewriteBodyOrigin replaces the checkpoint body's first line and re-signs,
// leaving the note name and everything else exactly as it was. The note still
// verifies under this network's key, so only §10's origin comparison can
// refuse the result.
func rewriteBodyOrigin(base, noteName, bodyOrigin string, key ed25519.PrivateKey,
	signers []cosignpkg.Signer) (string, error) {

	body, err := noteBody(base)
	if err != nil {
		return "", err
	}
	_, rest, found := strings.Cut(body, "\n")
	if !found {
		return "", fmt.Errorf("a checkpoint body has three lines")
	}
	signed, err := note.Sign(bodyOrigin+"\n"+rest, noteName, key)
	if err != nil {
		return "", err
	}
	return staggeredCosigner(signers)(signed)
}

// caseFlipped upper-cases the first letter of the origin's base32 tail, which
// §2 defines as lowercase. The string is otherwise byte-identical.
func caseFlipped(origin string) string {
	for i := 0; i < len(origin); i++ {
		if origin[i] >= 'a' && origin[i] <= 'z' && i > strings.Index(origin, "/") {
			return origin[:i] + string(origin[i]-32) + origin[i+1:]
		}
	}
	return origin
}

// shortRootLine re-encodes the root with one byte appended -- 33 bytes, whose
// first 32 are the honest root -- then re-signs and re-cosigns the body. The
// note is impeccable and the tree still matches for anyone who reads 32 bytes
// and stops; §6's "32 bytes once decoded" is the only rule that refuses it.
func shortRootLine(base, origin string, key ed25519.PrivateKey,
	signers []cosignpkg.Signer) (string, error) {

	body, err := noteBody(base)
	if err != nil {
		return "", err
	}
	lines := strings.SplitN(body, "\n", 3)
	if len(lines) < 3 {
		return "", fmt.Errorf("a checkpoint body has three lines, this has %d", len(lines))
	}
	// The third element carries the body's own terminating newline; §7 makes
	// that newline part of the note, so it has to survive the substitution.
	tail := strings.TrimRight(lines[2], "\n")
	root, err := base64.StdEncoding.DecodeString(tail)
	if err != nil {
		return "", fmt.Errorf("the root line is not base64: %w", err)
	}
	if len(root) != sha256.Size {
		return "", fmt.Errorf("the honest root is %d bytes, not %d", len(root), sha256.Size)
	}
	// A *longer* line, whose first 32 bytes are the honest root. Dropping a
	// byte instead would be caught by the rebuild below -- the truncated value
	// is not the tree's head -- so the length rule would be refused-but-not-
	// pinned. With a trailing byte, a reader that takes the first 32 and reads
	// on gets the right root, matches the tree, and accepts a checkpoint whose
	// root line is not a SHA-256 hash. Only the length says so.
	lines[2] = base64.StdEncoding.EncodeToString(append(root, 0x00)) +
		lines[2][len(tail):]
	signed, err := note.Sign(strings.Join(lines, "\n"), origin, key)
	if err != nil {
		return "", err
	}
	return staggeredCosigner(signers)(signed)
}

// rewriteLastSignature applies f to the final `— …` line of a signed note.
// The text and every earlier line are untouched, so the rewritten line is the
// only thing a reader can object to.
func rewriteLastSignature(signed string, f func(string) string) string {
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], note.SigPrefix) {
			lines[i] = f(lines[i])
			break
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// logSignatureLast moves the log's own signature line to the end of the block,
// so `rewriteLastSignature` can reach it. §10 says the log's line may appear
// anywhere and order carries nothing, so this changes no rule.
func logSignatureLast(signed, origin string) string {
	text, block, _ := strings.Cut(signed, "\n\n")
	var others, logLines []string
	for _, line := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
		if strings.HasPrefix(line, note.SigPrefix+origin+" ") {
			logLines = append(logLines, line)
		} else {
			others = append(others, line)
		}
	}
	all := append(others, logLines...)
	return text + "\n\n" + strings.Join(all, "\n") + "\n"
}

// nameWithSpace puts a space inside the key name. Splitting the line at its
// first space then leaves a payload that is not base64.
func nameWithSpace(line string) string {
	rest := strings.TrimPrefix(line, note.SigPrefix)
	name, blob, _ := strings.Cut(rest, " ")
	return note.SigPrefix + name + " extra " + blob
}

// dropPadding re-encodes the payload without its `=`.
func dropPadding(line string) string {
	rest := strings.TrimPrefix(line, note.SigPrefix)
	name, blob, _ := strings.Cut(rest, " ")
	return note.SigPrefix + name + " " + strings.TrimRight(blob, "=")
}

// nonzeroPadBits changes only the unused low bits of the last base64 data
// character. A permissive decoder gets the same bytes; RFC 4648 §3.5 refuses
// the alternate spelling.
func nonzeroPadBits(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded {
		return "", fmt.Errorf("input is not canonical padded base64")
	}
	padding := len(encoded) - len(strings.TrimRight(encoded, "="))
	if padding == 0 {
		return "", fmt.Errorf("base64 input has no unused pad bits")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	position := len(encoded) - padding - 1
	value := strings.IndexByte(alphabet, encoded[position])
	if value < 0 {
		return "", fmt.Errorf("base64 final data character is invalid")
	}
	mask := (1 << (padding * 2)) - 1
	mutated := []byte(encoded)
	mutated[position] = alphabet[(value&^mask)|1]
	return string(mutated), nil
}

func rewriteSignaturePadBits(signed, whose string) (string, error) {
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	prefix := note.SigPrefix + whose + " "
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.HasPrefix(lines[i], prefix) {
			continue
		}
		blob := strings.TrimPrefix(lines[i], prefix)
		bad, err := nonzeroPadBits(blob)
		if err != nil {
			return "", err
		}
		lines[i] = prefix + bad
		return strings.Join(lines, "\n") + "\n", nil
	}
	return "", fmt.Errorf("no signature line for %q", whose)
}

// appendByte adds one byte to the decoded payload, so it is 69 bytes where §7
// says 68 and a prefix-reading verifier sees no difference.
func appendByte(line string) string {
	rest := strings.TrimPrefix(line, note.SigPrefix)
	name, blob, _ := strings.Cut(rest, " ")
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return line
	}
	return note.SigPrefix + name + " " +
		base64.StdEncoding.EncodeToString(append(raw, 0x00))
}

// appendForgedLogSignature adds a second line under the log's own key that does
// not verify. Both name the log; a reader that takes the first valid one and
// stops never looks at the other.
func appendForgedLogSignature(signed, origin string) (string, error) {
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, note.SigPrefix+origin+" ") {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(
			strings.TrimPrefix(line, note.SigPrefix+origin+" "))
		if err != nil {
			return "", err
		}
		forged := append([]byte(nil), payload...)
		forged[len(forged)-1] ^= 0x01
		return strings.Join(lines, "\n") + "\n" +
			note.SignatureLine(origin, forged) + "\n", nil
	}
	return "", fmt.Errorf("no log signature line for %q", origin)
}

// appendForgedSecondLine gives one witness a second cosignature line: newer
// than its first, and not verifying. Everything else about the checkpoint is
// correct, so only a per-line reading of §10 can refuse it.
func appendForgedSecondLine(signed, whose string) (string, error) {
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "— "+whose+" ") {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(
			strings.TrimPrefix(line, "— "+whose+" "))
		if err != nil {
			return "", err
		}
		second := append([]byte(nil), payload...)
		// 4 bytes of key id, then a big-endian uint64 timestamp: one second
		// later, so a reader selecting the newest line selects this one.
		at := binary.BigEndian.Uint64(second[4:12])
		binary.BigEndian.PutUint64(second[4:12], at+1)
		second[len(second)-1] ^= 0x01
		return strings.Join(lines, "\n") + "\n" +
			note.SignatureLine(whose, second) + "\n", nil
	}
	return "", fmt.Errorf("no signature line for %q", whose)
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

// --- checkpoints-bad: the note layer's negatives (cold gate run 5, G2) ----
//
// §12.1 claimed these refusals for §6 and §10. Every one of them was a Go
// test in this repository and none of them was a file, so a second
// implementer received a suite of entirely valid notes: run 5 built a verifier
// that never checked a note or cosignature signature and passed all 597
// checks. A rule nobody can fail is a rule nobody has to implement.
//
// Each file is served in place of `served/checkpoint`, over the honest tiles,
// under the shipped `trust.cbor`. Everything else about the log is correct, so
// a refusal can only come from the checkpoint.
type badCheckpoint struct {
	Name   string
	Reason string
	Signed string
}

// noteBody is the checkpoint text a signature covers: origin, size, root, and
// the newline that ends the last of them.
func noteBody(signed string) (string, error) {
	i := strings.Index(signed, "\n\n")
	if i < 0 {
		return "", fmt.Errorf("checkpoint has no blank line before its signatures")
	}
	return signed[:i+1], nil
}

// forgeLastSignature flips a bit inside the newest signature line's payload,
// leaving its key id and any timestamp intact. The line stays syntactically
// perfect and stops verifying, which is the only construction that separates a
// verifier from one that pretends.
func forgeLastSignature(signed, whose string) (string, error) {
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.HasPrefix(lines[i], "— "+whose+" ") {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(
			strings.TrimPrefix(lines[i], "— "+whose+" "))
		if err != nil {
			return "", err
		}
		// The last byte is signature, never key id (4 bytes) or timestamp.
		payload[len(payload)-1] ^= 0x01
		lines[i] = note.SignatureLine(whose, payload)
		return strings.Join(lines, "\n") + "\n", nil
	}
	return "", fmt.Errorf("no signature line for %q", whose)
}

func buildBadCheckpoints(root, origin string, key ed25519.PrivateKey,
	signed string, signers []cosignpkg.Signer) ([]badCheckpoint, error) {

	body, err := noteBody(signed)
	if err != nil {
		return nil, err
	}
	// Re-signing the body must reproduce the log's own line: Ed25519 is
	// deterministic, and if it does not, every negative below is built over a
	// checkpoint that is not the one the suite serves.
	base, err := note.Sign(body, origin, key)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(signed, base) {
		return nil, fmt.Errorf("re-signing the checkpoint body did not reproduce the served signature")
	}
	stranger, err := seedKey(root, "stranger")
	if err != nil {
		return nil, err
	}
	cosignWith := func(base string, chosen ...cosignpkg.Signer) (string, error) {
		return staggeredCosigner(chosen)(base)
	}

	byName := map[string]cosignpkg.Signer{}
	for _, s := range signers {
		byName[s.Name] = s
	}

	var out []badCheckpoint

	out = append(out, badCheckpoint{"01-unsigned",
		"the checkpoint body with no signature line at all: nothing vouches for this tree",
		body + "\n"})

	wrongKey, err := note.Sign(body, origin, stranger)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"02-wrong-log-key",
		"signed under the log's own name by a key the anchor does not pin", wrongKey})

	elsewhere := "norn/elsewhere"
	otherBody := elsewhere + body[strings.Index(body, "\n"):]
	otherLog, err := note.Sign(otherBody, elsewhere, key)
	if err != nil {
		return nil, err
	}
	otherLog, err = cosignWith(otherLog, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"03-wrong-origin",
		"a perfectly valid checkpoint for another log: right key, wrong network", otherLog})

	forged, err := forgeLastSignature(base, origin)
	if err != nil {
		return nil, err
	}
	forged, err = cosignWith(forged, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"04-forged-log-signature",
		"the log's signature line is the right shape and the right key id, and does not verify", forged})

	short, err := cosignWith(base, byName["norn-witness/pi"])
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"05-one-cosignature-short",
		"one witness of the two the policy requires", short})

	out = append(out, badCheckpoint{"06-no-cosignatures",
		"signed by the log and cosigned by nobody", base})

	unnamed, err := cosignWith(base, cosignpkg.Signer{Name: "norn-witness/stranger", Key: stranger})
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"07-unnamed-witness-only",
		"cosigned only by a witness the policy never names, which counts for nothing", unnamed})

	forgedCosig, err := cosignWith(base, byName["norn-witness/pi"], byName["norn-witness/vps"])
	if err != nil {
		return nil, err
	}
	forgedCosig, err = forgeLastSignature(forgedCosig, "norn-witness/vps")
	if err != nil {
		return nil, err
	}
	// §6 fixes a checkpoint at three lines: origin, size, root, and **no
	// extension lines**. The rule was enforced and unvectored, so a second
	// implementer could accept a fourth line and pass everything shipped.
	// Signed and cosigned properly, so only the rule can refuse it.
	extended, err := note.Sign(body+"norn extension line\n", origin, key)
	if err != nil {
		return nil, err
	}
	extended, err = cosignWith(extended, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"09-extension-line",
		"a fourth body line, signed and cosigned exactly as correctly as the real one: " +
			"§6 allows origin, size and root and nothing else", extended})

	// H8: the origin line says which log a checkpoint is about, and the note
	// name and key id bind only the *signer*. This one is signed by the right
	// key under the right name, and claims to be another network's head.
	wrongBody := elsewhere + body[strings.Index(body, "\n"):]
	wrongOrigin, err := note.Sign(wrongBody, origin, key)
	if err != nil {
		return nil, err
	}
	wrongOrigin, err = cosignWith(wrongOrigin, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"10-wrong-body-origin",
		"signed by this network's log key, under this network's name, and its origin " +
			"line names another log", wrongOrigin})

	// `skip-cosig-verify`: all three named witnesses sign, two of them verify.
	// A reader that merely declines to count the bad line still has its quorum
	// of two and carries on; §10 says the checkpoint is refused. `08` cannot
	// tell those apart, because one valid line falls short either way.
	allThree, err := cosignWith(base, byName["norn-witness/pi"],
		byName["norn-witness/vps"], byName["norn-witness/friend"])
	if err != nil {
		return nil, err
	}
	withQuorum, err := forgeLastSignature(allThree, "norn-witness/friend")
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"11-forged-cosignature-with-quorum",
		"three named witnesses, two of whose cosignatures verify: the quorum is met " +
			"without the third, and §10 refuses the checkpoint anyway", withQuorum})

	// `cosig-all-lines`: §10 says "every cosignature by a witness the policy
	// names must verify"; §5.3 says two verifying lines from one witness are
	// its newest. Neither settled the case where one witness supplies both, so
	// a reader picking each witness's newest *verifying* line saw three good
	// witnesses and carried on. `11` is the neighbouring case and cannot stand
	// in for it: there the bad line's witness has no good line, so declining
	// to count it still leaves a quorum of two.
	secondLine, err := appendForgedSecondLine(allThree, "norn-witness/friend")
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"12-second-line-from-one-witness",
		"all three witnesses cosign and verify, and `friend` carries a second, newer " +
			"line that does not: a reader taking each witness's newest verifying line " +
			"sees a full quorum, and §10 refuses the checkpoint anyway", secondLine})

	// Cold gate run 8, D21: four framing rules §7 states, both
	// implementations enforce, and no file exercised. An ASCII hyphen instead
	// of U+2014 is what a reader writes who never looks at the bytes.
	out = append(out, badCheckpoint{"13-ascii-dash-signature",
		"the log's signature line opens with an ASCII hyphen instead of §7's em dash",
		strings.Replace(allThree, "\n"+note.SigPrefix, "\n- ", 1)})

	out = append(out, badCheckpoint{"14-unterminated-signature-block",
		"the last signature line does not end in a newline, so the block is unterminated",
		strings.TrimRight(allThree, "\n")})

	// A size line with a leading zero: two readers that parse it differently
	// disagree about which tree they are looking at.
	zeroPadded, err := paddedSizeLine(base, origin, key, signers)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"15-size-leading-zero",
		"the size line carries a leading zero, which is not canonical decimal", zeroPadded})

	// Two signature lines under the log's key, one of which does not verify.
	// The same shape as §10's per-line cosignature rule, on the log itself.
	twice, err := appendForgedLogSignature(allThree, origin)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"16-two-log-signatures",
		"two signature lines name the log's key and one does not verify: a reader " +
			"that stops at the first valid one accepts a checkpoint carrying a forgery",
		twice})

	// Cold gate run 10, D11. §6 bounds the root line at 32 bytes once decoded
	// and no file carried another length, so the only rule that ever looked at
	// that line was the rebuild-and-compare below it. Signed and cosigned
	// exactly as correctly as the real one, so the length is the whole fault.
	shortRoot, err := shortRootLine(base, origin, key, signers)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"17-root-wrong-length",
		"the root line decodes to 33 bytes whose first 32 are the honest root: a " +
			"reader that takes the first 32 and reads on matches the rebuilt tree " +
			"and accepts it, so §6's length is the only rule that can refuse it",
		shortRoot})

	// Cold gate run 10, D13. §7's framing left five splits to the reader and
	// three of them can be separated by a file. Each of these is `allThree`
	// with its **last** signature line rewritten one way, so the line is a
	// perfectly good signature under the lax reading and malformed under this
	// document's.
	out = append(out, badCheckpoint{"18-signature-name-with-space",
		"a signature line whose name carries a space: split at the first space the " +
			"payload is not base64, split at the last it is a signature from a name " +
			"nobody lists, which §10 ignores rather than refuses",
		rewriteLastSignature(allThree, nameWithSpace)})

	out = append(out, badCheckpoint{"19-signature-unpadded-base64",
		"the last signature line's payload is unpadded base64: the same bytes to a " +
			"raw-base64 reader, and not §7's encoding",
		rewriteLastSignature(allThree, dropPadding)})

	out = append(out, badCheckpoint{"20-signature-payload-too-long",
		"one byte appended to the log's 68-byte payload: a verifier that reads the " +
			"first 68 and stops verifies it, so this head has unboundedly many " +
			"byte-distinct forms that are all valid",
		rewriteLastSignature(logSignatureLast(allThree, origin), appendByte)})

	// Cold gate run 11, D7. §10's `require cp.origin == norn.trust.origin` was
	// separated from neither a prefix match nor a case-folded one: every origin
	// negative used an UNRELATED origin, so none of them is a prefix or a case
	// variant of this network's. §10 argues at length that the cosignature
	// match must be name AND key id because a name-only match hands anyone a
	// veto; this is the same argument from the other side, where a loose match
	// hands an attacker an acceptance.
	suffixed, err := rewriteBodyOrigin(base, origin, origin+"a", key, signers)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"21-origin-with-a-suffix",
		"the origin line is this network's origin plus one base32 character, " +
			"signed and cosigned exactly as correctly as the real head: a reader " +
			"matching on a prefix accepts it", suffixed})

	folded, err := rewriteBodyOrigin(base, origin, caseFlipped(origin), key, signers)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"22-origin-case-changed",
		"the same origin with one character in the other case: a reader folding " +
			"case accepts it, and §2's origin is lowercase base32 by construction",
		folded})

	// D14b. The final signature line already has its required LF. A second
	// one creates an empty line and is malformed note framing, not a terminator
	// that a parser may trim away.
	out = append(out, badCheckpoint{"23-extra-final-newline",
		"the final signature line ends in one LF and an extra LF adds a forbidden blank line",
		allThree + "\n"})

	// D14c. Framing permits both supported payload sizes before a key is
	// matched. Once name and key ID identify the trusted 0x01 log key, however,
	// a 76-byte payload cannot be its signature and must fail at log-signature.
	logVerifier, err := note.ParseVerifierKey(note.VerifierKey(origin,
		key.Public().(ed25519.PublicKey)))
	if err != nil {
		return nil, err
	}
	otherLength := append(append([]byte(nil), logVerifier.ID()...), make([]byte, 8+64)...)
	out = append(out, badCheckpoint{"24-log-key-other-algorithm-length",
		"a 76-byte payload under the log key's name and key ID is a log-signature failure, even beside its valid line",
		allThree + note.SignatureLine(logVerifier.Name, otherLength) + "\n"})

	// SEC-027, the same rule on the witness side. A 68-byte payload -- a note
	// signature's length -- under a listed witness's name and cosignature key
	// ID cannot be that witness's line. A reader that skips it as "not a
	// cosignature" still has three good lines and accepts the head; §7 and
	// §10.1 refuse it as `cosignature`.
	pi := byName["norn-witness/pi"]
	piID := note.KeyIDFor(pi.Name, pi.Key.Public().(ed25519.PublicKey), note.AlgCosignature)
	noteLength := append(append([]byte(nil), piID...), make([]byte, ed25519.SignatureSize)...)
	out = append(out, badCheckpoint{"28-witness-key-other-algorithm-length",
		"a 68-byte payload under a listed witness's name and cosignature key ID is a cosignature failure, even beside its valid line",
		allThree + note.SignatureLine(pi.Name, noteLength) + "\n"})

	// D14a. These mutations preserve the decoded bytes and every signature,
	// so the refusal belongs to canonical encoding rather than verification.
	badLogPayload, err := rewriteSignaturePadBits(allThree, origin)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"25-signature-nonzero-pad-bits",
		"the log signature payload has nonzero unused base64 pad bits but decodes to the same valid signature",
		badLogPayload})
	badCosignature, err := rewriteSignaturePadBits(allThree, "norn-witness/friend")
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"26-cosignature-nonzero-pad-bits",
		"a witness cosignature payload has nonzero unused base64 pad bits but decodes to the same valid cosignature",
		badCosignature})
	rootLines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	badRootEncoding, err := nonzeroPadBits(rootLines[2])
	if err != nil {
		return nil, err
	}
	rootLines[2] = badRootEncoding
	badRootBody := strings.Join(rootLines, "\n") + "\n"
	badRoot, err := note.Sign(badRootBody, origin, key)
	if err != nil {
		return nil, err
	}
	badRoot, err = cosignWith(badRoot, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"27-root-nonzero-pad-bits",
		"the root line has nonzero unused base64 pad bits but decodes to the same signed tree root",
		badRoot})

	out = append(out, badCheckpoint{"08-forged-cosignature",
		"two cosignature lines, both naming witnesses the policy lists, one of which does not verify: " +
			"the quorum is met only by a verifier that does not check them", forgedCosig})

	return out, nil
}

func writeBadCheckpoints(root, origin string, key ed25519.PrivateKey,
	signed string, signers []cosignpkg.Signer) error {

	cases, err := buildBadCheckpoints(root, origin, key, signed, signers)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "checkpoints-bad")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(cases))
	reasons := map[string]string{}
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(dir, c.Name+".checkpoint"), []byte(c.Signed), 0o644); err != nil {
			return err
		}
		names = append(names, c.Name)
		reasons[c.Name] = c.Reason
	}
	// Cold gate run 8, D6. The comment used to say "04 and 08 are the two a
	// signature-blind verifier accepts". That stopped being true when `11` was
	// added and again when `12` was: every one of these four is a checkpoint
	// whose ONLY defect is a signature of the right shape that does not
	// verify, so a reader that never calls Ed25519 accepts all four. Listed
	// rather than described, and checked below, because a sentence counting
	// files is a sentence that goes stale.
	blind := []string{
		"04-forged-log-signature",
		"08-forged-cosignature",
		"11-forged-cosignature-with-quorum",
		"12-second-line-from-one-witness",
		// Cold gate run 9, D6: this list is generated and its contents were
		// hand-written, so adding `16` silently falsified the claim that these
		// are the set "and nothing else here". `16`'s only defect is a second
		// log signature that does not verify, which a reader that never calls
		// Ed25519 cannot see. The set is now *computed* from the shipped files
		// by `TestTheSignatureBlindSetIsComputedNotAsserted`; this list is
		// checked against that computation rather than trusted.
		"16-two-log-signatures",
	}
	for _, want := range blind {
		if _, ok := reasons[want]; !ok {
			return fmt.Errorf("signature-blind list names %q, which is not a case", want)
		}
	}
	// Cold gate run 10. Every negative names the section that states the rule
	// it is about, and a phrase that must appear there. Without this a rule
	// can live in §12.1's coverage table and nowhere a reader will look --
	// which is how §7's terminating newline, §6's canonical size line and
	// §10's every-line rule all reached a gate unstated.
	rules := map[string]map[string]string{
		// 6.5l-vi-b-ii-d: these two cited a rule a later step states. 01 has
		// no signature line, so §7's framing refuses it before any signature
		// is looked for; 03 is signed under another origin's name, so the
		// signature refuses it before its origin is read. `codes` below made
		// the disagreement visible, and specdoc now holds the two together.
		"01-unsigned":                           {"section": "7", "says": "carries **at least one signature line**"},
		"02-wrong-log-key":                      {"section": "10", "says": "norn.trust.log_key"},
		"03-wrong-origin":                       {"section": "10", "says": "whatever origin it names"},
		"04-forged-log-signature":               {"section": "10", "says": "MUST\n  # verify"},
		"05-one-cosignature-short":              {"section": "10", "says": "the quorum must be satisfied"},
		"06-no-cosignatures":                    {"section": "10", "says": "the quorum must be satisfied"},
		"07-unnamed-witness-only":               {"section": "10", "says": "is IGNORED, not refused"},
		"08-forged-cosignature":                 {"section": "10", "says": "must verify"},
		"09-extension-line":                     {"section": "6", "says": "exactly three lines"},
		"10-wrong-body-origin":                  {"section": "10", "says": "which log this is about"},
		"11-forged-cosignature-with-quorum":     {"section": "10", "says": "per line, not per witness"},
		"12-second-line-from-one-witness":       {"section": "10", "says": "per line, not per witness"},
		"13-ascii-dash-signature":               {"section": "7", "says": "signature line per signer"},
		"14-unterminated-signature-block":       {"section": "7", "says": "including the last, ends in one"},
		"15-size-leading-zero":                  {"section": "6", "says": "no leading zeroes"},
		"17-root-wrong-length":                  {"section": "6", "says": "32 bytes once decoded"},
		"21-origin-with-a-suffix":               {"section": "10", "says": "cp.origin == norn.trust.origin"},
		"22-origin-case-changed":                {"section": "10", "says": "cp.origin == norn.trust.origin"},
		"23-extra-final-newline":                {"section": "7", "says": "a second `0x0A` after the final signature creates a forbidden blank line"},
		"24-log-key-other-algorithm-length":     {"section": "10", "says": "A 76-byte payload under the log's `0x01` key fails here"},
		"28-witness-key-other-algorithm-length": {"section": "10", "says": "A 68-byte payload under a listed witness's"},
		"25-signature-nonzero-pad-bits":         {"section": "7", "says": "unused pad bits MUST be zero"},
		"26-cosignature-nonzero-pad-bits":       {"section": "7", "says": "unused pad bits MUST be zero"},
		"27-root-nonzero-pad-bits":              {"section": "6", "says": "unused pad bits MUST be zero"},
		"18-signature-name-with-space":          {"section": "7", "says": "contains no space"},
		"19-signature-unpadded-base64":          {"section": "7", "says": "standard base64 **with padding**"},
		"20-signature-payload-too-long":         {"section": "7", "says": "The decoded payload is **exactly** that length"},
		"16-two-log-signatures":                 {"section": "10", "says": "Every signature line whose name and key id match"},
	}
	for name := range reasons {
		if _, ok := rules[name]; !ok {
			return fmt.Errorf("checkpoint case %q names no section: every negative must "+
				"say which section states the rule that refuses it", name)
		}
	}
	// D-061, §10.1: the code each file is refused with, in the order the
	// verifier checks. Without it a reader that runs two checks in the other
	// order refuses every file here too, and the suite cannot tell: 01 is
	// `note` and not `log-signature`, 03 is `log-signature` and not `origin`.
	codes := map[string]refusal.Code{
		"01-unsigned":                           refusal.Note,
		"02-wrong-log-key":                      refusal.LogSignature,
		"03-wrong-origin":                       refusal.LogSignature,
		"04-forged-log-signature":               refusal.LogSignature,
		"05-one-cosignature-short":              refusal.Quorum,
		"06-no-cosignatures":                    refusal.Quorum,
		"07-unnamed-witness-only":               refusal.Quorum,
		"08-forged-cosignature":                 refusal.Cosignature,
		"09-extension-line":                     refusal.Checkpoint,
		"10-wrong-body-origin":                  refusal.Origin,
		"11-forged-cosignature-with-quorum":     refusal.Cosignature,
		"12-second-line-from-one-witness":       refusal.Cosignature,
		"13-ascii-dash-signature":               refusal.Note,
		"14-unterminated-signature-block":       refusal.Note,
		"15-size-leading-zero":                  refusal.Checkpoint,
		"16-two-log-signatures":                 refusal.LogSignature,
		"17-root-wrong-length":                  refusal.Checkpoint,
		"18-signature-name-with-space":          refusal.Note,
		"19-signature-unpadded-base64":          refusal.Note,
		"20-signature-payload-too-long":         refusal.Note,
		"21-origin-with-a-suffix":               refusal.Origin,
		"22-origin-case-changed":                refusal.Origin,
		"23-extra-final-newline":                refusal.Note,
		"24-log-key-other-algorithm-length":     refusal.LogSignature,
		"25-signature-nonzero-pad-bits":         refusal.Note,
		"26-cosignature-nonzero-pad-bits":       refusal.Note,
		"27-root-nonzero-pad-bits":              refusal.Checkpoint,
		"28-witness-key-other-algorithm-length": refusal.Cosignature,
	}
	if err := checkCodes("checkpoints-bad", names, codes, refusal.Known); err != nil {
		return err
	}

	manifest := map[string]any{
		"cases":                   names,
		"reasons":                 reasons,
		"rules":                   rules,
		"signature_blind_accepts": blind,
		"codes":                   codes,
		"comment": "each file is served in place of served/checkpoint, over the honest tiles, " +
			"under trust.cbor; every one MUST be refused, with the SPEC §10.1 code `codes` " +
			"names for it. `signature_blind_accepts` lists the ones whose only defect is a " +
			"signature that does not verify: a reader that never calls Ed25519 accepts " +
			"exactly those, and nothing else here",
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(raw, '\n'), 0o644)
}
