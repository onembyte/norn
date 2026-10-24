package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/cbor"
	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/tlog"
)

// D-082 (4): inclusion is not acceptance. Rebuild the reader's five shapes
// with the fixture keys, each in a two-leaf tree with the genuine genesis,
// without changing the served log or the keys that condition 3 installs.
func writeD082Bundles(root, origin string, key ed25519.PrivateKey, entries [][]byte, signers []cosignpkg.Signer) error {
	const says = "Binding is structural: what replay judges against the anchor"
	for _, c := range []struct{ name, dir, code, hint string }{
		{"enroll-other-net", "proofs", "accept", "enroll envelope net is another network; inclusion accepts, replay refuses"},
		{"rotate-small-order-pk", "proofs", "accept", "rotate incoming device_pk has order 8; inclusion accepts, replay refuses"},
		{"rotate-open-body", "proofs", "accept", "rotate body has unknown x; inclusion accepts, replay refuses"},
		{"enroll-open-body", "proofs", "accept", "enroll body is {request, x}; inclusion accepts, replay refuses"},
		{"rotate-no-ts", "proofs-bad", "binding", `missing envelope key "ts"`},
	} {
		index := 35
		if c.name == "enroll-other-net" || c.name == "enroll-open-body" {
			index = 1
		}
		env, err := entry.Decode(entries[index])
		if err != nil {
			return err
		}
		env.Sigs = nil
		if index == 35 {
			prev := uint64(35)
			env.After, env.Prev, env.TS = nil, &prev, 1_760_009_000
		}
		switch c.name {
		case "enroll-other-net":
			env.Net = bytes.Repeat([]byte{0xff}, entry.NetLen)
		case "rotate-small-order-pk":
			pk, err := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
			if err != nil {
				return err
			}
			env.Body["device_pk"] = pk
		case "rotate-open-body", "enroll-open-body":
			env.Body["x"] = uint64(1)
		}
		// Sign the altered envelope, so the body and network cases do not
		// accidentally depend on a broken old signature. Missing ts is an
		// envelope fault and is removed after the typed signer has run.
		names := []string{"signer1", "signer2"}
		if index == 35 {
			names = []string{"signer1", "signer3", "nas"}
		}
		for _, name := range names {
			private, err := seedKey(root, name)
			if err != nil {
				return err
			}
			role := "signer"
			if name == "nas" {
				role = "device"
			}
			if err := entry.Sign(env, private, role); err != nil {
				return err
			}
		}
		raw, err := entry.Encode(env)
		if err != nil {
			return err
		}
		if c.name == "rotate-no-ts" {
			m := mustMap(raw)
			delete(m, "ts")
			raw, err = cbor.Encode(m)
			if err != nil {
				return err
			}
		}
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
		bundle, err := proof.Build("nas", 1, raw, path, head)
		if err != nil {
			return err
		}
		encoded, err := bundle.Encode()
		if err != nil {
			return err
		}
		if len(encoded) >= proof.MaxBundleBytes {
			return fmt.Errorf("D-082 %s hits the bundle cap", c.name)
		}
		if err := os.WriteFile(filepath.Join(root, c.dir, c.name+".bundle"), encoded, 0o644); err != nil {
			return err
		}
		m, err := d080Manifest(root, c.dir)
		if err != nil {
			return err
		}
		if c.code == "accept" {
			m["sound"] = append(m["sound"].([]any), map[string]any{
				"name": c.name, "file": c.name + ".bundle", "device": "nas", "index": 1, "says": c.hint,
			})
		} else {
			m["cases"] = append(m["cases"].([]any), map[string]string{"name": c.name, "says": c.hint})
		}
		m["codes"].(map[string]any)[c.name] = c.code
		phrase := says
		if c.code == "binding" {
			phrase = "`ts`, a map `body`, well-formed `sigs` — or it names no device"
		}
		m["rules"].(map[string]any)[c.name] = map[string]string{"section": "8.1", "says": phrase}
		if err := writeRunFourteenJSON(filepath.Join(root, c.dir, "cases.json"), m); err != nil {
			return err
		}
	}
	return nil
}
