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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlogstore"
)

// logKeySeed is a fixed test seed so the vectors are reproducible. It is
// published deliberately: these are vectors, not a network.
var logKeySeed = []byte("norn/vector/log-key/v1----------")

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
	store, err := tlogstore.Open(served, origin)
	if err != nil {
		return err
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			return err
		}
	}

	key := ed25519.NewKeyFromSeed(logKeySeed[:32])
	signed, err := store.Checkpoint().Sign(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(served, "checkpoint.signed"), []byte(signed), 0o644); err != nil {
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
		"origin":       origin,
		"log_key_seed": hex.EncodeToString(logKeySeed[:32]),
		"size":         store.Size(),
		"devices":      ids,
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
