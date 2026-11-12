package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

// Accept before replay drops friend. The forged copy then separates a held
// reader's accepting policy from an unheld reader's replayed policy.
func writeHeldPolicyHead(root string) error {
	raw, err := os.ReadFile(filepath.Join(root, "dropped-witness", "trust.cbor"))
	if err != nil {
		return err
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		return err
	}
	var entries [][]byte
	for _, name := range []string{"00-genesis.cbor", "01-policy-drops-friend.cbor"} {
		raw, err := os.ReadFile(filepath.Join(root, "dropped-witness", name))
		if err != nil {
			return err
		}
		entries = append(entries, raw)
	}
	st := replay.Replay(replay.FromTrust(doc), entries)
	if st.Size != 2 || len(st.Rejected) != 0 || st.Policy == doc.Policy {
		return fmt.Errorf("held-policy requires two accepted entries replacing the policy")
	}
	dir := filepath.Join(root, "held-policy")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	key, err := seedKey(root, "logkey")
	if err != nil {
		return err
	}
	signers, err := witnessSigners(root)
	if err != nil {
		return err
	}
	store, err := tlogstore.Open(filepath.Join(dir, "log"), doc.Origin, key, tlogstore.WithCosigner(tlogstore.CosignerFunc(staggeredCosigner(signers))))
	if err != nil {
		return err
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			return err
		}
	}
	head, err := store.SignedCheckpoint()
	if err != nil {
		return err
	}
	forged, err := forgeLastSignature(head, "norn-witness/friend")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "copy.checkpoint"), []byte(forged), 0o644); err != nil {
		return err
	}
	return writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"trust": "../dropped-witness/trust.cbor", "initial": "log", "replay": []string{"../dropped-witness/00-genesis.cbor", "../dropped-witness/01-policy-drops-friend.cbor"}, "copy": "copy.checkpoint",
		"readers": map[string]map[string]string{
			"held":     {"accept": "log", "replay": "accepted entries", "held_checkpoint": "log/checkpoint", "acceptance_policy": "trust.policy"},
			"replayed": {"replay": "replay", "held_checkpoint": "none", "policy": "replayed"},
		},
		"cases": []map[string]string{
			{"name": "held-forged-friend", "reader": "held", "file": "copy.checkpoint", "says": "friend was listed by the policy that accepted the held head"},
			{"name": "replayed-forged-friend", "reader": "replayed", "file": "copy.checkpoint", "says": "friend is unlisted under the replayed policy and no head is held"},
		},
		"codes":   map[string]string{"held-forged-friend": "cosignature", "replayed-forged-friend": "accept"},
		"retains": map[string]string{"checkpoint": "log/checkpoint", "policy": "trust.policy", "quorum_time": "initial acceptance"},
		"rules": map[string]map[string]string{
			"held-forged-friend":     {"section": "5.3", "says": "names a witness that policy lists, by name and key id"},
			"replayed-forged-friend": {"section": "9.4", "says": "A `policy` entry supersedes `norn.trust.policy` for every checkpoint"},
		},
	})
}
