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
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/proof"
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

	meta := map[string]any{
		"comment": "the served log and its proof bundles, produced by the Go " +
			"implementation and validated by upstream libraries; see SPEC 12",
		"origin": origin,
		// Named rather than repeated: the seed lives in keys.json, and a
		// second copy here is a second thing to keep in step.
		"log_key": "keys.json ed25519.logkey — the key trust.cbor names",
		"size":    store.Size(),
		"devices": ids,
		// §5.3's evaluation time, derived from this checkpoint's cosignature
		// timestamps under the shipped 2-of-3 policy. Recorded so a second
		// implementer can check their derivation rather than only their
		// proven set.
		"checkpoint_quorum_time": QuorumTimeOf(2),
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(bundles, "cases.json"), append(blob, '\n'), 0o644); err != nil {
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
	if err := writeBadServed(root, served, store.Size()); err != nil {
		return err
	}
	if err := writeRotatedHead(root, origin, signed, st, signers); err != nil {
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
		},
		"comment": "SPEC 8.1 condition 4 and 5.3's ladder, as a table: `elapsed` is the " +
			"node's monotonic time since it learned the checkpoint's quorum time, " +
			"`staleness` is the network's own from params, and `hard` is this node's " +
			"local S_hard. The rule is `elapsed > staleness`, so the boundary is still " +
			"fresh. A node with no corroborated instant has no clock and reports " +
			"`unknown` rather than guessing",
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

// writeBadProofs ships §8's four refusals. Each differs from a valid bundle in
// exactly one thing, so a verifier that skips one check accepts one file.
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

	meta := map[string]any{
		"log_key": note.VerifierKey(origin, key.Public().(ed25519.PublicKey)),
		"origin":  origin,
		"cases": []map[string]string{
			{"name": "open-schema", "says": "unknown field"},
			{"name": "wrong-version", "says": "unsupported version"},
			{"name": "device-not-in-entry", "says": "carries an entry about"},
			{"name": "no-quorum", "says": "no quorum cosigned"},
			{"name": "wrong-origin", "says": "is for origin"},
			{"name": "wrong-entry", "says": "inclusion proof"},
			{"name": "foreign-checkpoint", "says": "no valid signature from a trusted key"},
			{"name": "tampered-proof", "says": "inclusion proof"},
			{"name": "wrong-log-key", "says": "no valid signature from a trusted key"},
		},
		"comment": "bundles that MUST be refused under the log key above. Each differs " +
			"from a valid bundle in exactly one thing, so a verifier that skips one " +
			"check accepts exactly one of them",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

// writeBadServed ships §6's two refusals. A served log is a directory rather
// than a file, so the case says which path to replace or remove.
func writeBadServed(root, served string, size int64) error {
	dir := filepath.Join(root, "served-bad")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	bundlePath := tlog.EntryBundlePath(0, int(size%tlog.TileWidth))
	honest, err := os.ReadFile(filepath.Join(served, filepath.FromSlash(bundlePath)))
	if err != nil {
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
	tilePath := tlog.TilePath(0, 0, int(size%tlog.TileWidth))
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

	meta := map[string]any{
		"cases": []map[string]any{
			{"name": "tampered-entry-bundle", "path": bundlePath,
				"file": "tampered-entry-bundle.bin",
				"says": "one byte of one entry changed: the bundle still frames, and the " +
					"tree it builds is not the one the checkpoint is signed over"},
			{"name": "missing-entry-bundle", "path": bundlePath, "remove": true,
				"says": "a log that will not serve its entries cannot be replayed, and a " +
					"verifier must refuse rather than report what it has"},
			{"name": "tampered-hash-tile", "path": tilePath,
				"file": "tampered-hash-tile.bin",
				"says": "one byte of one leaf hash changed: the entries and the signed " +
					"head are untouched, so a verifier that reaches the head without " +
					"opening `tile/0/...` sees nothing wrong, and serves the corrupt " +
					"tile onward to peers asking it for proofs"},
		},
		"comment": "a served log is a directory, so each case names the path to replace " +
			"with `file` or to delete with `remove`, over an otherwise honest copy of " +
			"`served/`. Every one MUST be refused",
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
	branch := append([][]byte(nil), entries[:forkAt]...)
	divergent, err := forkEntry(root)
	if err != nil {
		return err
	}
	branch = append(branch, divergent)

	signers, err := witnessSigners(root)
	if err != nil {
		return err
	}
	forkedDir, err := os.MkdirTemp("", "norn-fork")
	if err != nil {
		return err
	}
	defer os.RemoveAll(forkedDir)

	store, err := tlogstore.Open(forkedDir, origin, key, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(staggeredCosigner(signers))))
	if err != nil {
		return err
	}
	for _, raw := range branch {
		if _, err := store.Append(raw); err != nil {
			return err
		}
	}
	forkedSigned, err := store.SignedCheckpoint()
	if err != nil {
		return err
	}
	forkedCP, err := tlog.Verify(forkedSigned, []string{note.VerifierKey(origin,
		key.Public().(ed25519.PublicKey))})
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
	return writeForkNegatives(root, origin, key, entries, heldSigned, heldTree, signers,
		evidence, forkedSigned, forkedCP)
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
	// An accuser can only speak for sizes its own branch reaches.
	aboveHeld := &forkevidence.Evidence{
		Held: heldSigned, Conflicting: forkedSigned,
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

	manifest := map[string]any{
		"cases": []map[string]string{
			{"name": "bad-open-schema", "says": "unknown field"},
			{"name": "bad-wrong-version", "says": "version"},
			{"name": "bad-size-above-held", "says": "can only speak for what it holds"},
			{"name": "bad-policy-says-quorum-none",
				"says": "no quorum cosigned it"},
			{"name": "bad-policy-unparseable",
				"says": "not a `tlog-policy`"},
			{"name": "bad-proof-at-same-size",
				"says": "requires none"},
			{"name": "bad-consistent",
				"says": "nothing here is a fork"},
			{"name": "bad-other-origin",
				"says": "the held checkpoint"},
			{"name": "bad-forged-proof",
				"says": "does not chain"},
			{"name": "bad-unverifiable-conflicting",
				"says": "the conflicting checkpoint"},
			{"name": "bad-size-mismatch",
				"says": "claims a disagreement"},
		},
		"comment": "evidence that MUST NOT be acted on, checked against trust.cbor. " +
			"bad-consistent is a log and its own earlier self -- every signature valid, " +
			"both heads cosigned, the roots agreeing. bad-other-origin is a real fork of " +
			"another network, which this anchor has no business accepting. `says` is what " +
			"the refusal must be about. `policy-not-the-readers.cbor` is not listed here: " +
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
	}
	for _, want := range blind {
		if _, ok := reasons[want]; !ok {
			return fmt.Errorf("signature-blind list names %q, which is not a case", want)
		}
	}
	manifest := map[string]any{
		"cases":                   names,
		"reasons":                 reasons,
		"signature_blind_accepts": blind,
		"comment": "each file is served in place of served/checkpoint, over the honest tiles, " +
			"under trust.cbor; every one MUST be refused. `signature_blind_accepts` lists " +
			"the ones whose only defect is a signature that does not verify: a reader that " +
			"never calls Ed25519 accepts exactly those, and nothing else here",
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(raw, '\n'), 0o644)
}
