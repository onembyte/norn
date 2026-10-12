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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

// QuorumTimeOf is the instant §5.3 derives from a set of cosignature
// timestamps under a k-of-n quorum: the newest instant at which k of them have
// answered. Computed here so the suite can record it for a second implementer.
func QuorumTimeOf(threshold int) int64 {
	// Witness i answers at CosignedAt + i*spread, so the k-th newest of n is
	// the one at index n-k.
	return CosignedAt + int64((len(WitnessNames)-threshold)*CosignSpread)
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
		"at_the_cap": map[string]any{
			"file": "at-the-cap.bundle", "bytes": proof.MaxBundleBytes, "accept": true,
		},
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
	if err := writeRotatedBundle(root); err != nil {
		return err
	}
	if err := writeExtraWitnessHead(root, signed, signers); err != nil {
		return err
	}
	if err := writeNameCollisionHead(root, signed, signers); err != nil {
		return err
	}
	if err := writeUnknownAlgorithmHead(root, signed); err != nil {
		return err
	}
	if err := writeStrangerNameHead(root, signed); err != nil {
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
	if err := writeServedGenesis(root); err != nil {
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
	doc := &trust.Trust{}
	var netText, genesisText string
	for _, line := range splitLines(string(trustRaw)) {
		for _, field := range []struct {
			name string
			into *string
		}{{"net", &netText}, {"genesis_hash", &genesisText}, {"origin", &doc.Origin}, {"log_key", &doc.LogKey}, {"policy", &doc.Policy}} {
			if value, ok := cutPrefix(line, field.name); ok {
				parsed, err := strconv.Unquote(value)
				if err != nil {
					return replay.Anchor{}, nil, "", err
				}
				*field.into = parsed
			}
		}
	}
	doc.Net, err = hex.DecodeString(netText)
	if err != nil {
		return replay.Anchor{}, nil, "", err
	}
	doc.GenesisHash, err = hex.DecodeString(genesisText)
	if err != nil {
		return replay.Anchor{}, nil, "", err
	}
	if !bytes.Equal(net, doc.Net) || !bytes.Equal(genesis, doc.GenesisHash) {
		return replay.Anchor{}, nil, "", fmt.Errorf("manifest and trust file anchors differ")
	}
	if doc.Origin == "" || doc.LogKey == "" || doc.Policy == "" {
		return replay.Anchor{}, nil, "", fmt.Errorf("trust.toml is missing origin, log_key or policy")
	}
	return replay.FromTrust(doc), entries, doc.Origin, nil
}
