package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/cbor"
	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/tlog"
)

// Run 21 separates bundle typing from structural entry binding. Each altered
// entry gets its own authenticated tree, including after its field is repaired.
func writeRunTwentyOneBundles(root, origin string, key ed25519.PrivateKey, entries [][]byte, signers []cosignpkg.Signer) error {
	parent, err := os.ReadFile(filepath.Join(root, "proofs", "nas.bundle"))
	if err != nil {
		return err
	}
	nas, err := seedKey(root, "nas")
	if err != nil {
		return err
	}
	rotate := mustMap(entries[35])
	repairs := map[string]any{}
	for _, name := range []string{"bool-v", "bool-index", "entry-prev-bool", "entry-after-bool", "entry-sigs-malformed-kid", "entry-net-15-bytes"} {
		section, phrase, code := "4.0", "schemas MUST reject them outside `params.rotate_needs_signer`", "bundle"
		var negative []byte
		repair := "../proofs/nas.bundle"
		if name == "bool-v" || name == "bool-index" {
			m := mustMap(parent)
			field := "v"
			if name == "bool-index" {
				field = "index"
			}
			m[field] = true
			negative, err = cbor.Encode(m)
			if err != nil {
				return err
			}
		} else {
			section, phrase, code = "8.1", "set of members, each of its type: `v` 1,", "binding"
			if name == "entry-sigs-malformed-kid" {
				phrase = "well-formed `sigs`"
			}
			if name == "entry-net-15-bytes" {
				phrase = "a 16-byte `net`"
			}
			repair = "../proofs/" + name + "-repaired.bundle"
			for _, hostile := range []bool{true, false} {
				env := map[string]any{"v": uint64(1), "t": "rotate", "ts": uint64(1760000700), "net": rotate["net"], "body": map[string]any{"device_id": "nas", "wg_pk": rotate["body"].(map[string]any)["wg_pk"]}}
				switch name {
				case "entry-prev-bool":
					if hostile {
						env["prev"] = true
					} else {
						env["prev"] = uint64(1)
					}
				case "entry-after-bool":
					if hostile {
						env["after"] = true
					} else {
						env["after"] = uint64(1)
					}
				case "entry-net-15-bytes":
					if hostile {
						env["net"] = env["net"].([]byte)[:15]
					}
				}
				pre, err := cbor.Encode(env)
				if err != nil {
					return err
				}
				kid := entry.Kid(nas.Public().(ed25519.PublicKey))
				if hostile && name == "entry-sigs-malformed-kid" {
					kid = "NOT-A-KID"
				}
				env["sigs"] = []any{map[string]any{"kid": kid, "role": "device", "sig": ed25519.Sign(nas, append([]byte(entry.PreimagePrefix), pre...))}}
				raw, err := cbor.Encode(env)
				if err != nil {
					return err
				}
				bundle, err := runTwentyOneBundle(origin, key, entries[0], raw, signers)
				if err != nil {
					return err
				}
				if hostile {
					negative = bundle
				} else {
					if err := os.WriteFile(filepath.Join(root, "proofs-bad", repair), bundle, 0o644); err != nil {
						return err
					}
					m, err := d080Manifest(root, "proofs")
					if err != nil {
						return err
					}
					n := name + "-repaired"
					m["sound"] = append(m["sound"].([]any), map[string]any{"name": n, "file": n + ".bundle", "device": "nas", "index": 1, "says": "only the binding field repaired, with renewed authentication"})
					m["codes"].(map[string]any)[n] = "accept"
					m["rules"].(map[string]any)[n] = map[string]string{"section": section, "says": phrase}
					if err := writeRunFourteenJSON(filepath.Join(root, "proofs", "cases.json"), m); err != nil {
						return err
					}
				}
			}
		}
		if err := os.WriteFile(filepath.Join(root, "proofs-bad", name+".bundle"), negative, 0o644); err != nil {
			return err
		}
		if err := extendRunFourteenManifest(root, "proofs-bad", []map[string]string{{"name": name, "says": map[string]string{
			"bool-v": "bundle v is true rather than uint 1", "bool-index": "bundle index is true rather than uint 1", "entry-prev-bool": "optional envelope prev is a boolean", "entry-after-bool": "optional envelope after is a boolean", "entry-sigs-malformed-kid": "bundled entry sigs has a malformed kid", "entry-net-15-bytes": "envelope net is 15 bytes",
		}[name]}}, map[string]string{name: code}, map[string]map[string]string{name: {"section": section, "says": phrase}}, false); err != nil {
			return err
		}
		repairs[name] = repair
	}
	m, err := d080Manifest(root, "proofs-bad")
	if err != nil {
		return err
	}
	m["repairs"] = repairs
	return writeRunFourteenJSON(filepath.Join(root, "proofs-bad", "cases.json"), m)
}

func runTwentyOneBundle(origin string, key ed25519.PrivateKey, genesis, raw []byte, signers []cosignpkg.Signer) ([]byte, error) {
	tree, err := tlog.Build([][]byte{genesis, raw})
	if err != nil {
		return nil, err
	}
	signed, err := tree.Checkpoint(origin).Sign(key)
	if err != nil {
		return nil, err
	}
	signed, err = staggeredCosigner(signers)(signed)
	if err != nil {
		return nil, err
	}
	path, err := tree.InclusionProof(1)
	if err != nil {
		return nil, err
	}
	b, err := proof.Build("nas", 1, raw, path, signed)
	if err != nil {
		return nil, err
	}
	return b.Encode()
}
