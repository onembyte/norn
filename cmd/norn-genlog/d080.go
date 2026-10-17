// These vectors ship D-080's Go half without moving the served checkpoint.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/cbor"
	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/tlog"
)

func writeD080(root, origin string, key ed25519.PrivateKey, entries [][]byte, signed string, signers []cosignpkg.Signer) error {
	if len(entries) != 162 {
		return fmt.Errorf("D-080 requires the unchanged 162-entry log")
	}
	if err := writeD080Evidence(root, origin, signers); err != nil {
		return err
	}
	if err := writeD080GrownLog(root); err != nil {
		return err
	}
	return writeD080Bundles(root, origin, key, entries, signed, signers)
}

func writeD080Evidence(root, origin string, signers []cosignpkg.Signer) error {
	raw, err := os.ReadFile(filepath.Join(root, "fork/evidence.cbor"))
	if err != nil {
		return err
	}
	ev, err := forkevidence.Parse(raw)
	if err != nil {
		return err
	}
	key, err := seedKey(root, "logkey2")
	if err != nil {
		return err
	}
	// Both log signatures rotate together; the signed text, witnesses and
	// consistency proofs remain those of the original sound fork.
	resign := func(head string) (string, error) {
		next, err := note.Sign(mustBody(head), origin, key)
		if err != nil {
			return "", err
		}
		return staggeredCosigner(signers)(next)
	}
	ev.Held, err = resign(ev.Held)
	if err != nil {
		return err
	}
	ev.Conflicting, err = resign(ev.Conflicting)
	if err != nil {
		return err
	}
	raw, err = ev.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "fork/evidence-rotated-key.cbor"), raw, 0o644); err != nil {
		return err
	}
	m, err := d080Manifest(root, "fork")
	if err != nil {
		return err
	}
	// The existing cases list is for trust-file-only refusals. This file has
	// two answers, with the same reader names as proofs-rotated/cases.json.
	m["rotated_key"] = map[string]any{
		"file": "evidence-rotated-key.cbor", "fresh": "held", "informed": "accept",
		"signed_by": hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		"comment":   "fresh holds only trust.cbor; informed verified and replayed served through the rotation, retaining the trust key and using the replayed policy. Both heads are signed by proofs-rotated's logkey2.",
	}
	m["rules"].(map[string]any)["evidence-rotated-key"] = map[string]string{"section": "11.1", "says": "trust file issued since; one holding only the older trust file answers `held`,"}
	return writeRunFourteenJSON(filepath.Join(root, "fork/cases.json"), m)
}

func writeD080GrownLog(root string) error {
	dir := filepath.Join(root, "grown-log")
	var cases []map[string]string
	codes := map[string]string{}
	rules := map[string]map[string]string{}
	for _, c := range []struct{ name, path, code, hint string }{
		{"full-tile-trailing-bytes", "tile/0/000", "tiles", "two bytes after the full tile's 256 hashes"},
		{"full-tile-truncated", "tile/0/000", "tiles", "full tile cut to the head's 162 hashes"},
		{"full-bundle-trailing-bytes", "tile/entries/000", "entries", "two bytes after the full bundle's 256 frames"},
	} {
		raw, err := os.ReadFile(filepath.Join(dir, c.path))
		if err != nil {
			return err
		}
		if c.name == "full-tile-truncated" {
			raw = raw[:162*32]
		} else {
			raw = append(raw, 0, 0)
		}
		if err := os.WriteFile(filepath.Join(dir, c.name+".bin"), raw, 0o644); err != nil {
			return err
		}
		cases = append(cases, map[string]string{"name": c.name, "path": c.path, "file": c.name + ".bin", "says": c.hint})
		codes[c.name] = c.code
		phrase := "a longer or shorter one is `tiles` (step 12)"
		if c.code == "entries" {
			phrase = "any other count is `entries` (step 8)"
		}
		rules[c.name] = map[string]string{"section": "10.1", "says": phrase}
	}
	return extendRunFourteenManifest(root, "grown-log", cases, codes, rules, false)
}

func writeD080Bundles(root, origin string, key ed25519.PrivateKey, entries [][]byte, signed string, signers []cosignpkg.Signer) error {
	// Reuse the real nas rotation as the sound twin. Only the wrapped entry's
	// size or envelope version changes; the two-leaf head commits that leaf.
	for _, name := range []string{"oversize-entry", "rotate-v2"} {
		env := mustMap(entries[35])
		if name == "rotate-v2" {
			env["v"] = uint64(2)
		} else {
			body := env["body"].(map[string]any)
			pad := 65000
			for range 8 {
				body["padding"] = make([]byte, pad)
				raw, err := cbor.Encode(env)
				if err != nil {
					return err
				}
				if len(raw) == cbor.MaxEntryBytes+1 {
					break
				}
				pad += cbor.MaxEntryBytes + 1 - len(raw)
			}
		}
		raw, err := cbor.Encode(env)
		if err != nil {
			return err
		}
		if name == "oversize-entry" && len(raw) != 65536 {
			return fmt.Errorf("oversize rotate is %d bytes", len(raw))
		}
		// A hostile log can sign an unservable leaf. Build its tree directly:
		// the honest store's uint16 entry framing cannot carry the oversize one.
		tree, err := tlog.Build([][]byte{entries[0], raw})
		if err != nil {
			return err
		}
		head, err := tree.Checkpoint(origin).Sign(key)
		if err != nil {
			return err
		}
		head, err = staggeredCosigner(signers)(head)
		if err != nil {
			return err
		}
		path, err := tree.InclusionProof(1)
		if err != nil {
			return err
		}
		b, err := proof.Build("nas", 1, raw, path, head)
		if err != nil {
			return err
		}
		encoded, err := b.Encode()
		if err != nil {
			return err
		}
		if len(encoded) >= proof.MaxBundleBytes {
			return fmt.Errorf("D-080 %s hits the bundle cap", name)
		}
		if err := os.WriteFile(filepath.Join(root, "proofs-bad", name+".bundle"), encoded, 0o644); err != nil {
			return err
		}
	}
	if err := extendRunFourteenManifest(root, "proofs-bad", []map[string]string{
		{"name": "oversize-entry", "says": "MAX_ENTRY_BYTES"}, {"name": "rotate-v2", "says": "the bundled entry does not decode"},
	}, map[string]string{"oversize-entry": "bundle", "rotate-v2": "binding"}, map[string]map[string]string{
		"oversize-entry": {"section": "10.1", "says": "or an `entry` longer than `MAX_ENTRY_BYTES` (D-080)"},
		"rotate-v2":      {"section": "8.1", "says": "entry itself must decode under §4.0's profile and §4.1's envelope — version 1,"},
	}, false); err != nil {
		return err
	}
	tree, err := tlog.Build(entries)
	if err != nil {
		return err
	}
	m, err := d080Manifest(root, "proofs")
	if err != nil {
		return err
	}
	for _, c := range []struct {
		name  string
		index int64
	}{{"forged", 98}, {"halfsigned", 57}} {
		path, err := tree.InclusionProof(c.index)
		if err != nil {
			return err
		}
		b, err := proof.Build(c.name, c.index, entries[c.index], path, signed)
		if err != nil {
			return err
		}
		raw, err := b.Encode()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, "proofs", c.name+".bundle"), raw, 0o644); err != nil {
			return err
		}
		m["sound"] = append(m["sound"].([]any), map[string]any{"name": c.name, "file": c.name + ".bundle", "device": c.name, "index": c.index, "says": "inclusion accepts; replay refused the enrollment, so installs omits " + c.name})
		m["codes"].(map[string]any)[c.name] = "accept"
		m["rules"].(map[string]any)[c.name] = map[string]string{"section": "8.1", "says": "§3.1's point admission included; its signature and network are not part of"}
	}
	return writeRunFourteenJSON(filepath.Join(root, "proofs/cases.json"), m)
}

func d080Manifest(root, dir string) (map[string]any, error) {
	raw, err := os.ReadFile(filepath.Join(root, dir, "cases.json"))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
