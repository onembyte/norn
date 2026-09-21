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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
	if err := writeSupersededHead(root, origin, signed, key, signers); err != nil {
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

	meta := map[string]any{
		"log_key": note.VerifierKey(origin, key.Public().(ed25519.PublicKey)),
		"origin":  origin,
		"cases": []map[string]string{
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

	meta := map[string]any{
		"cases": []map[string]any{
			{"name": "tampered-entry-bundle", "path": bundlePath,
				"file": "tampered-entry-bundle.bin",
				"says": "one byte of one entry changed: the bundle still frames, and the " +
					"tree it builds is not the one the checkpoint is signed over"},
			{"name": "missing-entry-bundle", "path": bundlePath, "remove": true,
				"says": "a log that will not serve its entries cannot be replayed, and a " +
					"verifier must refuse rather than report what it has"},
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

	manifest := map[string]any{
		"cases": []map[string]string{
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
			"the refusal must be about",
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
	withQuorum, err := cosignWith(base, byName["norn-witness/pi"],
		byName["norn-witness/vps"], byName["norn-witness/friend"])
	if err != nil {
		return nil, err
	}
	withQuorum, err = forgeLastSignature(withQuorum, "norn-witness/friend")
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"11-forged-cosignature-with-quorum",
		"three named witnesses, two of whose cosignatures verify: the quorum is met " +
			"without the third, and §10 refuses the checkpoint anyway", withQuorum})

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
	manifest := map[string]any{
		"cases":   names,
		"reasons": reasons,
		"comment": "each file is served in place of served/checkpoint, over the honest tiles, " +
			"under trust.cbor; every one MUST be refused. 04 and 08 are the two that a " +
			"verifier which never checks a signature will accept",
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(raw, '\n'), 0o644)
}
