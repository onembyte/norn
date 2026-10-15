// These vectors hold run 16's remaining head rules and their artifact twins.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/trust"
)

func writeRunSixteenPlainRules(root, signed string, entries [][]byte) error {
	if err := writeRunSixteenHeads(root, signed, entries); err != nil {
		return err
	}
	// All entries and the signed root stay honest. Only a higher-level tile
	// differs, so a reader that checks leaf tiles alone misses this corruption.
	const tileCase = "level-one-byte-changed"
	raw, err := os.ReadFile(filepath.Join(root, "served-large", "tile/1/000.p/1"))
	if err != nil {
		return err
	}
	raw[0] ^= 1
	if err := os.WriteFile(filepath.Join(root, "served-large-bad", tileCase+".bin"), raw, 0o644); err != nil {
		return err
	}
	if err := extendRunFourteenManifest(root, "served-large-bad", []map[string]string{{"name": tileCase, "path": "tile/1/000.p/1", "file": tileCase + ".bin", "says": "one changed byte in the width-1 level-1 hash tile"}}, map[string]string{tileCase: "tiles"}, map[string]map[string]string{tileCase: {"section": "10", "says": "require every served hash tile == the rebuilt tree's"}}, false); err != nil {
		return err
	}

	// Flip only the version of each sound twin. Version 1 forbids all four
	// split fields, and version 2 requires them; the fork itself stays real.
	for _, c := range []struct {
		name, twin string
		version    uint64
	}{
		{"bad-v1-split-keys", "evidence.cbor", 1},
		{"bad-v2-without-split-keys", "evidence-v1.cbor", 2},
	} {
		raw, err := os.ReadFile(filepath.Join(root, "fork", c.twin))
		if err != nil {
			return err
		}
		value := mustMap(raw)
		value["version"] = c.version
		raw, err = cbor.Encode(value)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, "fork", c.name+".cbor"), raw, 0o644); err != nil {
			return err
		}
		hint := "unknown field"
		if c.version == 2 {
			hint = "missing fields"
		}
		if err := extendRunFourteenManifest(root, "fork", []map[string]string{{"name": c.name, "says": hint}}, map[string]string{c.name: "schema"}, map[string]map[string]string{c.name: {"section": "11.1", "says": "the map is not the closed set of exactly seven keys (version 1) or eleven (version 2)"}}, false); err != nil {
			return err
		}
	}
	return writeRunSixteenRotateBundle(root, signed, entries)
}

func writeRunSixteenHeads(root, signed string, entries [][]byte) error {
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		return err
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "heads-run16")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "trust.cbor"), raw, 0o644); err != nil {
		return err
	}
	body, sigs, err := note.Split(signed)
	if err != nil {
		return err
	}
	var pi note.Signature
	for _, sig := range sigs {
		if sig.Name == "norn-witness/pi" {
			pi = sig
		}
	}
	if pi.Name == "" {
		return fmt.Errorf("fixture head has no pi line")
	}
	key3, err := seedKey(root, "logkey3")
	if err != nil {
		return err
	}
	policyKey := note.VerifierKey(doc.Origin, key3.Public().(ed25519.PublicKey))
	var policyLines []string
	for _, line := range strings.Split(doc.Policy, "\n") {
		if strings.HasPrefix(line, "log ") {
			fields := strings.Fields(line)
			fields[1] = policyKey
			line = strings.Join(fields, " ")
		}
		policyLines = append(policyLines, line)
	}
	updated := strings.Join(policyLines, "\n")
	genesis := replay.Replay(replay.FromTrust(doc), entries[:1])
	env := &entry.Envelope{V: entry.Version, T: "policy", Net: doc.Net, TS: CosignedAt - 100, Prev: genesis.Previous("policy", ""), Body: map[string]any{"text": updated}}
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
	policyHead, err := note.Sign(body, doc.Origin, key3)
	if err != nil {
		return err
	}
	forged, err := forgeLastSignature(signed, "norn-witness/pi")
	if err != nil {
		return err
	}
	// Keep the log and pi only. Repairing pi leaves a genuine quorum failure;
	// the forged pi must be checked before that failure is reported.
	text, block, _ := strings.Cut(forged, "\n\n")
	var kept []string
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(line, note.SigPrefix+doc.Origin+" ") || strings.HasPrefix(line, note.SigPrefix+"norn-witness/pi ") {
			kept = append(kept, line)
		}
	}
	forged = text + "\n\n" + strings.Join(kept, "\n") + "\n"
	cases := []map[string]string{
		{"name": "stranger-log-id", "file": "stranger-log-id.checkpoint", "reader": "fresh", "says": "a stranger name carrying only the log's key id names no trusted key"},
		{"name": "stranger-pi-id", "file": "stranger-pi-id.checkpoint", "reader": "fresh", "says": "a stranger name carrying only pi's key id names no listed witness"},
		{"name": "stranger-del", "file": "stranger-del.checkpoint", "reader": "fresh", "says": "DEL is permitted in a stranger signature name"},
		{"name": "stranger-three-bytes", "file": "stranger-three-bytes.checkpoint", "reader": "fresh", "says": "three decoded bytes cannot carry the four-byte key id"},
		{"name": "policy-log-only", "file": "policy-log-only.checkpoint", "reader": "informed", "says": "replay genesis and policy; logkey3 is named only on the policy log line, never by log_key"},
		{"name": "forged-pi-without-quorum", "file": "forged-pi-without-quorum.checkpoint", "reader": "fresh", "says": "the forged pi line is cosignature before the independently short quorum"},
	}
	heads := []string{
		signed + note.SignatureLine("stranger/log", sigs[0].KeyID) + "\n",
		signed + note.SignatureLine("stranger/pi", pi.KeyID) + "\n",
		signed + note.SignatureLine("stranger/\x7f", []byte{0, 1, 2, 3}) + "\n",
		signed + note.SignatureLine("stranger/short", []byte{0, 1, 2}) + "\n",
		policyHead, forged,
	}
	for i, c := range cases {
		if err := os.WriteFile(filepath.Join(dir, c["file"]), []byte(heads[i]), 0o644); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		file string
		raw  []byte
	}{{"00-genesis.cbor", entries[0]}, {"01-policy-logkey3.cbor", policyEntry}} {
		if err := os.WriteFile(filepath.Join(dir, item.file), item.raw, 0o644); err != nil {
			return err
		}
	}

	// A request reader has a network in hand, unlike requests-bad's decoder.
	// Keep its semantic answers separate from the checkpoint's closed codes.
	requestKey, err := seedKey(root, "stranger")
	if err != nil {
		return err
	}
	requests := []map[string]any{}
	for _, other := range []bool{false, true} {
		net := append([]byte(nil), doc.Net...)
		name := "request-this-network"
		if other {
			net[0] ^= 1
			name = "request-other-network"
		}
		request, err := enrollreq.New(net, "nas", requestKey.Public().(ed25519.PublicKey), make([]byte, 32), CosignedAt-100, nil, nil)
		if err != nil {
			return err
		}
		if err := enrollreq.Sign(request, requestKey); err != nil {
			return err
		}
		raw, err := enrollreq.Encode(request)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name+".cbor"), raw, 0o644); err != nil {
			return err
		}
		requests = append(requests, map[string]any{"name": name, "file": name + ".cbor", "accept": !other, "says": "verify the signature, then require net to equal consumer_net before displaying the request"})
	}
	return writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"trust": "trust.cbor", "serve_over": "served", "replay": []string{"00-genesis.cbor", "01-policy-logkey3.cbor"},
		"cases": cases,
		"codes": map[string]string{"stranger-log-id": "accept", "stranger-pi-id": "accept", "stranger-del": "accept", "stranger-three-bytes": "note", "policy-log-only": "log-signature", "forged-pi-without-quorum": "cosignature"},
		"rules": map[string]map[string]string{
			"stranger-log-id":          {"section": "7", "says": "What follows the key id is judged by the trusted key whose name and key id"},
			"stranger-pi-id":           {"section": "7", "says": "What follows the key id is judged by the trusted key whose name and key id"},
			"stranger-del":             {"section": "7", "says": "MUST NOT contain an ASCII control character below U+0020"},
			"stranger-three-bytes":     {"section": "7", "says": "and canonical padded base64 that decodes to at least the 4-byte `key_id`."},
			"policy-log-only":          {"section": "9.1", "says": "Norn takes the log key it verifies with from `log_key`, never from here"},
			"forged-pi-without-quorum": {"section": "10.1", "says": "a cosignature line whose name **and** key id match a listed witness does not verify"},
		},
		"requests": map[string]any{"consumer_net": hex.EncodeToString(doc.Net), "cases": requests, "rules": map[string]map[string]string{
			"request-this-network":  {"section": "16.1", "says": "MUST also refuse a request whose `net` is not the network it serves, before"},
			"request-other-network": {"section": "16.1", "says": "MUST also refuse a request whose `net` is not the network it serves, before"},
		}},
		"comment": "Serve every head over served's honest tiles. Fresh readers use only trust.cbor; the informed reader replays the two named entries in order and uses the replacement policy, retaining only keys published through log_key. Requests are checked separately with consumer_net, not as checkpoints; accept is a semantic result, not a new refusal code.",
	})
}

func writeRunSixteenRotateBundle(root, signed string, entries [][]byte) error {
	const index = 35
	env, err := entry.Decode(entries[index])
	if err != nil || env.T != "rotate" || env.Body["device_id"] != "nas" {
		return fmt.Errorf("fixture index 35 is not nas's rotate: %v", err)
	}
	tree, err := tlog.Build(entries)
	if err != nil {
		return err
	}
	path, err := tree.InclusionProof(index)
	if err != nil {
		return err
	}
	bundle, err := proof.Build("nas", index, entries[index], path, signed)
	if err != nil {
		return err
	}
	raw, err := bundle.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "proofs", "nas-rotate.bundle"), raw, 0o644); err != nil {
		return err
	}
	manifestPath := filepath.Join(root, "proofs", "cases.json")
	raw, err = os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	// The device list still means the activating entries. Add a separate sound
	// list so the positive rotation does not change any existing case's meaning.
	manifest["sound"] = []map[string]any{{"name": "nas-rotate", "file": "nas-rotate.bundle", "device": "nas", "index": index, "says": "a rotate is bound through device_id in its body"}}
	manifest["codes"] = map[string]string{"nas-rotate": "accept"}
	manifest["rules"] = map[string]map[string]string{"nas-rotate": {"section": "8.1", "says": "types, the `device_id` in the body — and apply the rules below."}}
	return writeRunFourteenJSON(manifestPath, manifest)
}
