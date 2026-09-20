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

// CosignedAt is the fixed instant the fixture's witnesses cosign at.
//
// Fixed, because a vector whose bytes changed with the clock could not be
// compared to anything. Witness time is the clock elsewhere (GOSSIP.md part
// 5); here it is a number the suite agrees on.
const CosignedAt = 1_760_003_600

// witnessSigners loads the fixture's witnesses in the order the policy lists
// them, so the cosignature lines land in a fixed order and the fixture stays
// byte-reproducible.
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
		tlogstore.CosignerFunc(cosignpkg.Append(signers, cosignpkg.At(time.Unix(CosignedAt, 0))))))
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
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(bundles, "cases.json"), append(blob, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("served %d entries to %s, %d proof bundles\n", store.Size(), served, len(ids))
	return nil
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
		tlogstore.CosignerFunc(cosignpkg.Append(signers, cosignpkg.At(time.Unix(CosignedAt, 0))))))
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
	return writeForkNegatives(root, origin, key, entries, heldSigned, heldTree, signers)
}

// writeForkNegatives ships the two refusals §12.1 has claimed since Phase 4.
// Neither existed as a file: the first was exercised by a Go test against the
// *valid* vector, and the second could not be exercised at all, because
// `forkevidence.Build` refuses to produce it. A reader given only this
// directory could check that a fork is proved and nothing about what is not.
func writeForkNegatives(root, origin string, key ed25519.PrivateKey,
	entries [][]byte, heldSigned string, heldTree *tlog.Tree,
	signers []cosignpkg.Signer) error {

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

	manifest := map[string]any{
		"cases": []map[string]string{
			{"name": "bad-consistent",
				"says": "nothing here is a fork"},
			{"name": "bad-other-origin",
				"says": "the held checkpoint"},
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

// signedHeadOver builds a cosigned checkpoint over exactly these entries.
func signedHeadOver(root, origin string, key ed25519.PrivateKey,
	entries [][]byte, signers []cosignpkg.Signer) (string, error) {

	dir, err := os.MkdirTemp("", "norn-branch")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	store, err := tlogstore.Open(dir, origin, key, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(cosignpkg.Append(signers, cosignpkg.At(time.Unix(CosignedAt, 0))))))
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
	at := cosignpkg.At(time.Unix(CosignedAt, 0))
	cosignWith := func(base string, chosen ...cosignpkg.Signer) (string, error) {
		return cosignpkg.Append(chosen, at)(base)
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
