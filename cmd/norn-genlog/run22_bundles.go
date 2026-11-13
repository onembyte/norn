package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/onembyte/norn/internal/cbor"
	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
)

// These two bundles prove authentic enrolments before the stored view's
// revocation and rotation. The separate directory does not alter the main
// proof manifest's one-bundle-per-active-device installation contract.
func writeOlderHeadBundles(root, origin string, key ed25519.PrivateKey, entries [][]byte, signers []cosignpkg.Signer) error {
	if len(entries) != 162 {
		return fmt.Errorf("older-head bundles require the served size-162 log")
	}
	anchor, _, _, err := loadFixture(root)
	if err != nil {
		return err
	}
	stored := replay.Replay(anchor, entries)
	older := replay.Replay(anchor, entries[:10])
	tree, err := tlog.Build(entries[:10])
	if err != nil {
		return err
	}
	head, err := tree.Checkpoint(origin).Sign(key)
	if err != nil {
		return err
	}
	head, err = cosignpkg.Append(signers, func() time.Time { return time.Unix(1760001000, 0) })(head)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "proofs-older-head")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cases := []map[string]any{}
	installs, olderInstalls := map[string]string{}, map[string]string{}
	for _, id := range []string{"laptop", "nas"} {
		index := int64(1)
		if id == "laptop" {
			index = 2
		}
		path, err := tree.InclusionProof(index)
		if err != nil {
			return err
		}
		b, err := proof.Build(id, index, entries[index], path, head)
		if err != nil {
			return err
		}
		raw, err := b.Encode()
		if err != nil {
			return err
		}
		name := id + "-older-head"
		if err := os.WriteFile(filepath.Join(dir, name+".bundle"), raw, 0o644); err != nil {
			return err
		}
		if d := stored.Devices[id]; d.Status == "active" {
			installs[id] = d.WgPk
		}
		if d := older.Devices[id]; d.Status == "active" {
			olderInstalls[id] = d.WgPk
		}
		says := "nas installs the key replay gives at the stored head, not its key at the older bundle head"
		if id == "laptop" {
			says = "laptop was active at the bundle head but is revoked at the stored head; installs omits it"
		}
		cases = append(cases, map[string]any{"name": name, "file": name + ".bundle", "device": id, "index": index, "head_size": 10, "consistent": true, "says": says})
	}
	return writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"comment": "The reader holds served's verified size-162 checkpoint and replayed state. Both bundles have a quorum-cosigned size-10 head consistent with it. Bundle acceptance proves inclusion, not the current key.",
		"trust":   "../trust.cbor", "stored_checkpoint": "../served/checkpoint", "stored_log": "../served",
		"reader": map[string]string{"policy": "replayed", "held_checkpoint": "../served/checkpoint"},
		"cases":  cases, "codes": map[string]string{"laptop-older-head": "accept", "nas-older-head": "accept"},
		"installs": installs, "bundle_head_installs": olderInstalls,
		"rules": map[string]any{
			"laptop-older-head": map[string]string{"section": "8.1", "says": "replay of the log up to **the node's stored checkpoint**"},
			"nas-older-head":    map[string]string{"section": "8.1", "says": "the key the node installs for it is **the `wg_pk` replay gives**"},
		},
	})
}

// The existing oversized-entry negative pins the upper side. This sound
// two-leaf tree pins the inclusive boundary without implying installation.
func writeRunTwentyTwoEntryCap(root, origin string, key ed25519.PrivateKey, entries [][]byte, signers []cosignpkg.Signer) error {
	env := mustMap(entries[35])
	body := env["body"].(map[string]any)
	pad := 65000
	var raw []byte
	var err error
	for range 8 {
		body["padding"] = make([]byte, pad)
		raw, err = cbor.Encode(env)
		if err != nil {
			return err
		}
		if len(raw) == cbor.MaxEntryBytes {
			break
		}
		pad += cbor.MaxEntryBytes - len(raw)
	}
	if len(raw) != cbor.MaxEntryBytes {
		return fmt.Errorf("cap entry is %d bytes", len(raw))
	}
	encoded, err := runTwentyOneBundle(origin, key, entries[0], raw, signers)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "proofs", "entry-at-the-cap.bundle"), encoded, 0o644); err != nil {
		return err
	}
	m, err := d080Manifest(root, "proofs")
	if err != nil {
		return err
	}
	m["sound"] = append(m["sound"].([]any), map[string]any{"name": "entry-at-the-cap", "file": "entry-at-the-cap.bundle", "device": "nas", "index": 1, "says": "a 65535-byte entry reaches the inclusive entry cap inside a valid bundle"})
	m["codes"].(map[string]any)["entry-at-the-cap"] = "accept"
	m["rules"].(map[string]any)["entry-at-the-cap"] = map[string]string{"section": "8.1", "says": "at most `MAX_ENTRY_BYTES`"}
	return writeRunFourteenJSON(filepath.Join(root, "proofs", "cases.json"), m)
}
