// These vectors hold exact proof consumption and the policy's witness list
// after a root-authorised replacement, without moving the stamped head.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
	upstream "golang.org/x/mod/sumdb/tlog"
)

func writeRunSixteen(root, signed string, entries [][]byte) error {
	raw, err := os.ReadFile(filepath.Join(root, "proofs", "nas.bundle"))
	if err != nil {
		return err
	}
	bundle, err := proof.Decode(raw)
	if err != nil {
		return err
	}
	bundle.Proof = append(bundle.Proof, upstream.Hash{})
	raw, err = bundle.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "proofs-bad", "padded-proof.bundle"), raw, 0o644); err != nil {
		return err
	}
	if err := extendRunFourteenManifest(root, "proofs-bad", []map[string]string{{"name": "padded-proof", "says": "inclusion proof"}}, map[string]string{"padded-proof": "inclusion"}, map[string]map[string]string{"padded-proof": {"section": "10.1", "says": "the proof carries more or fewer hashes than RFC 9162 §2.1.3.2 consumes"}}, false); err != nil {
		return err
	}

	// Each file adds one hash to a sound non-empty path. The other two paths
	// stay sound, so the split case reaches its own check in step 8.
	for _, name := range []string{"bad-padded-proof", "bad-padded-split-proof"} {
		raw, err := os.ReadFile(filepath.Join(root, "fork", "evidence.cbor"))
		if err != nil {
			return err
		}
		ev, err := forkevidence.Parse(raw)
		if err != nil {
			return err
		}
		path := &ev.Proof
		hint := "the proof does not chain"
		if name == "bad-padded-split-proof" {
			path = &ev.SplitProofHeld
			hint = "the held split proof does not chain"
		}
		if len(*path) == 0 {
			return fmt.Errorf("%s needs a non-empty sound proof", name)
		}
		*path = append(*path, make([]byte, 32))
		raw, err = ev.Encode()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, "fork", name+".cbor"), raw, 0o644); err != nil {
			return err
		}
		phrase := "the consistency proof does not chain `held_root` at `size` to the held checkpoint's signed head"
		if name == "bad-padded-split-proof" {
			phrase = "a split proof does not chain `split_root` at `split` to its head"
		}
		if err := extendRunFourteenManifest(root, "fork", []map[string]string{{"name": name, "says": hint}}, map[string]string{name: "proof"}, map[string]map[string]string{name: {"section": "11.1", "says": phrase}}, false); err != nil {
			return err
		}
	}
	return writeDroppedWitness(root, signed, entries)
}

func writeDroppedWitness(root, signed string, entries [][]byte) error {
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		return err
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "dropped-witness")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "trust.cbor"), raw, 0o644); err != nil {
		return err
	}

	// Retain every other policy line and require the two remaining witnesses.
	// The trust file itself retains all three names and keys.
	var lines []string
	for _, line := range strings.Split(doc.Policy, "\n") {
		if strings.HasPrefix(line, "witness friend ") {
			continue
		}
		lines = append(lines, strings.Replace(line, "group home 2 pi vps friend", "group home 2 pi vps", 1))
	}
	updated := strings.Join(lines, "\n")
	anchor := replay.FromTrust(doc)
	genesis := replay.Replay(anchor, entries[:1])
	env := &entry.Envelope{
		V: entry.Version, T: "policy", Net: doc.Net, TS: CosignedAt - 100,
		Prev: genesis.Previous("policy", ""), Body: map[string]any{"text": updated},
	}
	for _, name := range []string{"root1", "root2", "root3"} {
		key, err := seedKey(root, name)
		if err != nil {
			return err
		}
		if err := entry.Sign(env, key, "root"); err != nil {
			return err
		}
	}
	policyEntry, err := entry.Encode(env)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		file string
		raw  []byte
	}{{"00-genesis.cbor", entries[0]}, {"01-policy-drops-friend.cbor", policyEntry}} {
		if err := os.WriteFile(filepath.Join(dir, item.file), item.raw, 0o644); err != nil {
			return err
		}
	}
	forged, err := forgeLastSignature(signed, "norn-witness/friend")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "forged-friend.checkpoint"), []byte(forged), 0o644); err != nil {
		return err
	}
	return writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"trust": "trust.cbor", "serve_over": "served",
		"replay": []string{"00-genesis.cbor", "01-policy-drops-friend.cbor"},
		"cases": []map[string]string{
			{"name": "friend-after-drop", "file": "forged-friend.checkpoint", "reader": "informed", "says": "replay both entries on this trust anchor, then ignore friend's line under the replacement policy"},
			{"name": "friend-before-replay", "file": "forged-friend.checkpoint", "reader": "fresh", "says": "without replay, the trust policy still names friend and its matching signature does not verify"},
		},
		"codes": map[string]string{"friend-after-drop": "accept", "friend-before-replay": "cosignature"},
		"rules": map[string]map[string]string{
			"friend-after-drop":    {"section": "10.1", "says": "listed meaning named by the policy in force (§9.4), not a witness a `policy` entry has dropped that the trust file still lists"},
			"friend-before-replay": {"section": "9.4", "says": "A node holding only the trust file uses its policy."},
		},
		"comment": "The trust file still lists pi, vps and friend. Replay the fixture genesis and root-signed policy entry in the stated order on that anchor; both apply, and the replacement policy names only pi and vps, requiring both. Serve the same forged head over served's honest tiles to both readers. Only the policy in force differs; the head is not checked retroactively under the policy its own entries publish (SPEC 9.4).",
	})
}
