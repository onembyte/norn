// These vectors close run 14's gaps in Go-owned artifacts without extending
// the 162-entry replay fixture or changing its stamped served checkpoint.
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
	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlog"
)

func writeRunFourteen(root, origin string, key ed25519.PrivateKey, entries [][]byte,
	signed string, anchor replay.Anchor, signers []cosignpkg.Signer) error {
	if err := writeRunFourteenCheckpoints(root, origin, key, entries, signed, signers); err != nil {
		return err
	}
	if err := writeRunFourteenEvidence(root, origin, key, signers); err != nil {
		return err
	}
	if err := writeRunFourteenServed(root, origin, key, entries, anchor, signers); err != nil {
		return err
	}
	return writeRunFourteenRotations(root, origin, entries, signed, anchor, signers)
}

// extendRunFourteenManifest adds cases to the manifest its original writer
// just produced. The original cases retain their order and their metadata.
func extendRunFourteenManifest(root, dir string, cases []map[string]string, codes map[string]string, rules map[string]map[string]string, bare bool) error {
	path := filepath.Join(root, dir, "cases.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	listed := manifest["cases"].([]any)
	for _, c := range cases {
		if bare {
			listed = append(listed, c["name"])
			manifest["reasons"].(map[string]any)[c["name"]] = c["says"]
		} else {
			listed = append(listed, c)
		}
	}
	manifest["cases"] = listed
	if manifest["rules"] == nil {
		manifest["rules"] = map[string]any{}
	}
	for name, code := range codes {
		manifest["codes"].(map[string]any)[name] = code
	}
	for name, rule := range rules {
		manifest["rules"].(map[string]any)[name] = rule
	}
	if dir == "proofs-bad" {
		manifest["comment"] = strings.Replace(manifest["comment"].(string), "except no-quorum-tampered-proof", "except wrong-version-and-untrusted-checkpoint and no-quorum-tampered-proof", 1)
	}
	if dir == "checkpoints-bad" {
		names := make([]string, 0, len(listed))
		for _, name := range listed {
			names = append(names, name.(string))
		}
		blind, err := signatureBlindCheckpoints(root, names)
		if err != nil {
			return err
		}
		manifest["signature_blind_accepts"] = blind
	}
	return writeRunFourteenJSON(path, manifest)
}

func writeRunFourteenJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func writeRunFourteenCheckpoints(root, origin string, key ed25519.PrivateKey, entries [][]byte, signed string, signers []cosignpkg.Signer) error {
	body := mustBody(signed)
	wrongBody := "elsewhere/log" + body[strings.Index(body, "\n"):]
	sign := func(body string, witnesses bool) (string, error) {
		head, err := note.Sign(body, origin, key)
		if err != nil || !witnesses {
			return head, err
		}
		return staggeredCosigner(signers)(head)
	}
	four, err := sign(wrongBody+"extension\n", true)
	if err != nil {
		return err
	}
	wrong, err := sign(wrongBody, true)
	if err != nil {
		return err
	}
	forged, err := forgeLastSignature(wrong, "norn-witness/pi")
	if err != nil {
		return err
	}
	tree, err := tlog.Build(append(append([][]byte(nil), entries...), []byte{0x00}))
	if err != nil {
		return err
	}
	future := tlog.Checkpoint{Origin: origin, Size: 163, Root: tree.Head()}
	noQuorum, err := sign(future.Marshal(), false)
	if err != nil {
		return err
	}
	for name, head := range map[string]string{
		"34-four-lines-and-wrong-origin": four,
		"35-wrong-origin-and-forged-pi":  forged,
		"36-no-quorum-and-size-163":      noQuorum,
		"37-crlf":                        strings.ReplaceAll(signed, "\n", "\r\n"),
	} {
		if err := os.WriteFile(filepath.Join(root, "checkpoints-bad", name+".checkpoint"), []byte(head), 0o644); err != nil {
			return err
		}
	}
	return extendRunFourteenManifest(root, "checkpoints-bad", []map[string]string{
		{"name": "34-four-lines-and-wrong-origin", "says": "four body lines and another origin: the body is checked first"},
		{"name": "35-wrong-origin-and-forged-pi", "says": "another origin and a forged pi line: the origin is checked first"},
		{"name": "36-no-quorum-and-size-163", "says": "a log-only head one entry beyond served: quorum decides before fetching entries"},
		{"name": "37-crlf", "says": "the honest head with every LF changed to CRLF: no note framing"},
	}, map[string]string{"34-four-lines-and-wrong-origin": "checkpoint", "35-wrong-origin-and-forged-pi": "origin", "36-no-quorum-and-size-163": "quorum", "37-crlf": "note"}, map[string]map[string]string{
		"34-four-lines-and-wrong-origin": {"section": "6", "says": "exactly three lines"},
		"35-wrong-origin-and-forged-pi":  {"section": "10", "says": "cp.origin == norn.trust.origin"},
		"36-no-quorum-and-size-163":      {"section": "10", "says": "the quorum must be satisfied"},
		"37-crlf":                        {"section": "7", "says": "including the last, ends in one"},
	}, true)
}

func writeRunFourteenEvidence(root, origin string, key ed25519.PrivateKey, signers []cosignpkg.Signer) error {
	dir := filepath.Join(root, "fork")
	sound, err := os.ReadFile(filepath.Join(dir, "evidence-v1.cbor"))
	if err != nil {
		return err
	}
	m := mustMap(sound)
	m["policy"] = "this is not a tlog-policy\n"
	badPolicy, err := cbor.Encode(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-policy-unparseable-and-unknown-key.cbor"), withExtraKey(badPolicy, "surprise", "an unpermitted evidence key"), 0o644); err != nil {
		return err
	}
	m = mustMap(sound)
	// Keep the held-root claim and its proof sound at the evidence size.
	// Only the conflicting head's size and log signature are wrong.
	conflictingCP, err := tlog.ParseCheckpoint(mustBody(m["conflicting"].(string)))
	if err != nil {
		return err
	}
	conflictingCP.Size++
	wrongSize, err := conflictingCP.Sign(key)
	if err != nil {
		return err
	}
	wrongSize, err = staggeredCosigner(signers)(wrongSize)
	if err != nil {
		return err
	}
	forged, err := forgeLastSignature(wrongSize, origin)
	if err != nil {
		return err
	}
	m["conflicting"] = forged
	badSize, err := cbor.Encode(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-unverifiable-conflicting-and-size-mismatch.cbor"), badSize, 0o644); err != nil {
		return err
	}
	tree, err := tlog.Build(nil)
	if err != nil {
		return err
	}
	held := tlog.Checkpoint{Origin: origin, Size: 0, Root: tree.Head()}
	conflicting := held
	conflicting.Root[0] ^= 1
	sign := func(cp tlog.Checkpoint) (string, error) {
		head, err := cp.Sign(key)
		if err != nil {
			return "", err
		}
		return staggeredCosigner(signers)(head)
	}
	heldHead, err := sign(held)
	if err != nil {
		return err
	}
	conflictingHead, err := sign(conflicting)
	if err != nil {
		return err
	}
	ev := &forkevidence.Evidence{Held: heldHead, Conflicting: conflictingHead, Size: 0, HeldRoot: append([]byte(nil), held.Root[:]...), Policy: policyOf(root)}
	zero, err := encodeVersionOne(ev)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-size-zero-empty-held.cbor"), zero, 0o644); err != nil {
		return err
	}
	if err := extendRunFourteenManifest(root, "fork", []map[string]string{
		{"name": "bad-policy-unparseable-and-unknown-key", "says": "unknown field"},
		{"name": "bad-unverifiable-conflicting-and-size-mismatch", "says": "the conflicting checkpoint"},
		{"name": "bad-size-zero-empty-held", "says": "at size 0"},
	}, map[string]string{"bad-policy-unparseable-and-unknown-key": "schema", "bad-unverifiable-conflicting-and-size-mismatch": "conflicting", "bad-size-zero-empty-held": "proof"}, map[string]map[string]string{
		"bad-policy-unparseable-and-unknown-key":         {"section": "11.1", "says": "the map is not the closed set of exactly seven keys"},
		"bad-unverifiable-conflicting-and-size-mismatch": {"section": "11.1", "says": "the conflicting checkpoint fails any §10 check"},
		"bad-size-zero-empty-held":                       {"section": "11.1", "says": "no file can show a disagreement at size 0"},
	}, false); err != nil {
		return err
	}
	// The bundle differs only in its version and checkpoint signer. Its
	// honest entry and inclusion proof still belong to the same tree.
	base, err := os.ReadFile(filepath.Join(root, "proofs", "nas.bundle"))
	if err != nil {
		return err
	}
	m = mustMap(base)
	stranger, err := seedKey(root, "stranger")
	if err != nil {
		return err
	}
	head, err := note.Sign(mustBody(m["checkpoint"].(string)), origin, stranger)
	if err != nil {
		return err
	}
	head, err = staggeredCosigner(signers)(head)
	if err != nil {
		return err
	}
	m["checkpoint"] = head
	m["v"] = uint64(2)
	bundle, err := cbor.Encode(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "proofs-bad", "wrong-version-and-untrusted-checkpoint.bundle"), bundle, 0o644); err != nil {
		return err
	}
	return extendRunFourteenManifest(root, "proofs-bad", []map[string]string{{"name": "wrong-version-and-untrusted-checkpoint", "says": "unsupported version"}}, map[string]string{"wrong-version-and-untrusted-checkpoint": "bundle"}, map[string]map[string]string{"wrong-version-and-untrusted-checkpoint": {"section": "8.1", "says": "`v` | uint | `1`"}}, false)
}

func writeRunFourteenServed(root, origin string, key ed25519.PrivateKey, entries [][]byte, anchor replay.Anchor, signers []cosignpkg.Signer) error {
	dir := filepath.Join(root, "served-empty-entry")
	emptyEntries := [][]byte{entries[0], entries[1], {}, entries[2]}
	if _, err := serveInto(dir, origin, key, emptyEntries, signers); err != nil {
		return err
	}
	st := replay.Replay(anchor, emptyEntries)
	raw, err := st.MarshalCanonical()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0o644); err != nil {
		return err
	}
	if err := writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"size": 4, "cases": []map[string]string{{"name": "zero-length-entry", "says": "accepted checkpoint, empty entry at index 2 rejected by replay as decode"}},
		"codes": map[string]string{"zero-length-entry": "accept"}, "replay_codes": map[string]string{"2": "decode"},
		"rules":   map[string]map[string]string{"zero-length-entry": {"section": "10.1", "says": "a uint16 length of 0 is a frame"}},
		"comment": "A four-entry log with a zero-length frame between real entries, its honest rebuilt tree, signed and cosigned head, and expected replayed state.",
	}); err != nil {
		return err
	}
	dir = filepath.Join(root, "served-large-bad")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, path := range map[string]string{"full-entry-bundle-trailing-bytes": "tile/entries/000", "full-hash-tile-trailing-bytes": "tile/0/000"} {
		raw, err := os.ReadFile(filepath.Join(root, "served-large", path))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name+".bin"), append(raw, 0, 0), 0o644); err != nil {
			return err
		}
	}
	if err := writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"serve_over": "served-large",
		"cases": []map[string]string{
			{"name": "full-entry-bundle-trailing-bytes", "path": "tile/entries/000", "file": "full-entry-bundle-trailing-bytes.bin", "says": "two trailing bytes after 256 entry frames"},
			{"name": "full-hash-tile-trailing-bytes", "path": "tile/0/000", "file": "full-hash-tile-trailing-bytes.bin", "says": "two trailing bytes after 256 leaf hashes"},
		}, "codes": map[string]string{"full-entry-bundle-trailing-bytes": "entries", "full-hash-tile-trailing-bytes": "tiles"},
		"rules": map[string]map[string]string{
			"full-entry-bundle-trailing-bytes": {"section": "10.1", "says": "Bytes after the last frame a full bundle needs"},
			"full-hash-tile-trailing-bytes":    {"section": "10.1", "says": "compared byte for byte, length included"},
		}, "comment": "Replace each named full width-256 path over served-large. Only the trailing bytes differ.",
	}); err != nil {
		return err
	}
	for _, name := range []string{"other-genesis-missing-tile", "other-genesis-tampered-tile"} {
		dir = filepath.Join(root, "detect", name)
		if _, err := serveInto(dir, origin, key, entries[1:forkAt+1], signers); err != nil {
			return err
		}
		path := filepath.Join(dir, tlog.TilePath(0, 0, forkAt))
		if strings.Contains(name, "missing") {
			if err := os.Remove(path); err != nil {
				return err
			}
		} else {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			raw[0] ^= 1
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				return err
			}
		}
	}
	return extendRunFourteenManifest(root, "served-genesis", []map[string]string{
		{"name": "other-genesis-missing-tile", "serve": "../detect/other-genesis-missing-tile", "says": "entry 0 is not the anchored genesis, before the missing hash tile is fetched"},
		{"name": "other-genesis-tampered-tile", "serve": "../detect/other-genesis-tampered-tile", "says": "entry 0 is not the anchored genesis, before the changed hash tile is compared"},
	}, map[string]string{"other-genesis-missing-tile": "genesis", "other-genesis-tampered-tile": "genesis"}, map[string]map[string]string{
		"other-genesis-missing-tile":  {"section": "10.1", "says": "its entry 0 is not the genesis the anchor pins"},
		"other-genesis-tampered-tile": {"section": "10.1", "says": "its entry 0 is not the genesis the anchor pins"},
	}, false)
}

func writeRunFourteenRotations(root, origin string, entries [][]byte, signed string, anchor replay.Anchor, signers []cosignpkg.Signer) error {
	key, err := seedKey(root, "logkey2")
	if err != nil {
		return err
	}
	// The manifests name the signer as served-rotated's does: the published
	// key's bytes in hex, with its log_key entry's since_index and overlap.
	published := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	var learned *state.LogKey
	for _, k := range replay.Replay(anchor, entries).LogKeys {
		if k.Pk == published {
			learned = &k
			break
		}
	}
	if learned == nil {
		return fmt.Errorf("the fixture never publishes logkey2")
	}
	for _, c := range []struct {
		dir, name, informed, comment string
		earlier                      bool
	}{
		{"served-rotated-wrong-name", "elsewhere/log", "log-signature",
			"the served head, signed by logkey2 under the name elsewhere/log instead of the network's origin. " +
				"Serve it in place of served/checkpoint over the same tiles. A reader holding only trust.cbor (`fresh`) " +
				"refuses it as log-signature, and so does one that has replayed served (`informed`): the key it learned " +
				"is named the origin, as the trust file's log key is (SPEC 9.4)", false},
		{"served-rotated-earlier", origin, "accept",
			"a complete 20-entry log whose head logkey2 signs, though logkey2's log_key entry is at index 27 of served. " +
				"A reader holding only trust.cbor (`fresh`) refuses it as log-signature; one that has replayed served " +
				"(`informed`) accepts it: a learned key verifies any head, with no activation index on the verifier's side (SPEC 9.4)", true},
	} {
		dir := filepath.Join(root, c.dir)
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		body := mustBody(signed)
		if c.earlier {
			head, err := serveInto(dir, origin, key, entries[:20], signers)
			if err != nil {
				return err
			}
			body = mustBody(head)
		} else {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		head, err := note.Sign(body, c.name, key)
		if err != nil {
			return err
		}
		head, err = staggeredCosigner(signers)(head)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
			return err
		}
		phrase := "named the origin, as the trust file's log key is"
		if c.earlier {
			phrase = "There is no separate activation index and"
		}
		meta := map[string]any{
			"fresh": "log-signature", "informed": c.informed,
			"signed_by": learned.Pk, "since_index": learned.SinceIndex, "overlap": learned.Overlap,
			"cases":   []map[string]string{{"name": "fresh", "says": "the reader has not learned logkey2"}, {"name": "informed", "says": "the reader has replayed served and learned logkey2"}},
			"codes":   map[string]string{"fresh": "log-signature", "informed": c.informed},
			"rules":   map[string]map[string]string{"fresh": {"section": "9.4", "says": "accepted nothing has only the trust file's key"}, "informed": {"section": "9.4", "says": phrase}},
			"comment": c.comment,
		}
		if !c.earlier {
			meta["serve_over"] = "served"
		}
		if err := writeRunFourteenJSON(filepath.Join(dir, "cases.json"), meta); err != nil {
			return err
		}
	}
	return nil
}
