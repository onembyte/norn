// These vectors hold run 17's Go-side gaps without changing the replay log.
package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/cbor"
	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/trust"
)

func writeRunSeventeen(root, origin string, key ed25519.PrivateKey, entries [][]byte, signed string, signers []cosignpkg.Signer) error {
	if len(entries) != 162 {
		return fmt.Errorf("run 17 requires the unchanged 162-entry log")
	}
	if err := writeRunSeventeenEvidence(root); err != nil {
		return err
	}
	if err := writeRunSeventeenBundles(root, origin, key, entries, signed, signers); err != nil {
		return err
	}
	if err := writeReplayedPolicy(root); err != nil {
		return err
	}
	if err := writeQuorumNone(root, signed, entries); err != nil {
		return err
	}
	return writeGenesisUnapplied(root, origin, key, entries, signers)
}

func writeRunSeventeenEvidence(root string) error {
	raw, err := os.ReadFile(filepath.Join(root, "fork/evidence.cbor"))
	if err != nil {
		return err
	}
	ev, err := forkevidence.Parse(raw)
	if err != nil {
		return err
	}
	ev.Split = 0
	ev.SplitRoot = make([]byte, 32)
	ev.SplitRoot[0] = 1
	ev.SplitProofHeld, ev.SplitProofConflicting = nil, nil
	split, err := ev.Encode()
	if err != nil {
		return err
	}
	// An empty key is a profile violation, so the normal encoder cannot write
	// it. Prepend its canonical pair before the eleven existing sorted keys.
	if raw[0] != 0xab {
		return fmt.Errorf("sound evidence must have eleven map pairs")
	}
	emptyKey := append([]byte{0xac, 0x60, 0x00}, raw[1:]...)
	cases := []struct {
		name, code, section, says, hint string
		raw                             []byte
	}{
		{"bad-split-zero-with-a-root", "proof", "11.1", "`split` is 0 with a `split_root` that is not all zero (step 4)", "all-zero root", split},
		{"bad-declared-length-past-the-file", "cbor", "11.1", "It is the file's own length: a short file whose CBOR declares more than it holds is `cbor`, not `oversize`", "truncated", []byte{0x7a, 0, 1, 0x11, 0x70, 's', 'h', 'o', 'r', 't'}},
		{"bad-empty-map-key", "cbor", "4.0", "every **map key** is a text string of 1–23 bytes", "map key must be 1-23 bytes", emptyKey},
	}
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(root, "fork", c.name+".cbor"), c.raw, 0o644); err != nil {
			return err
		}
		if err := extendRunFourteenManifest(root, "fork", []map[string]string{{"name": c.name, "says": c.hint}}, map[string]string{c.name: c.code}, map[string]map[string]string{c.name: {"section": c.section, "says": c.says}}, false); err != nil {
			return err
		}
	}
	return nil
}

func writeRunSeventeenBundles(root, origin string, key ed25519.PrivateKey, entries [][]byte, signed string, signers []cosignpkg.Signer) error {
	raw, err := os.ReadFile(filepath.Join(root, "proofs/nas.bundle"))
	if err != nil {
		return err
	}
	m := mustMap(raw)
	hashes := m["proof"].([]any)
	if len(hashes) == 0 {
		return fmt.Errorf("nas needs a nonempty inclusion proof")
	}
	hashes[0] = hashes[0].([]byte)[:31]
	short, err := cbor.Encode(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "proofs-bad/short-proof-hash.bundle"), short, 0o644); err != nil {
		return err
	}
	tree, err := tlog.Build(entries)
	if err != nil {
		return err
	}
	path, err := tree.InclusionProof(81)
	if err != nil {
		return err
	}
	b, err := proof.Build("probe", 81, entries[81], path, signed)
	if err != nil {
		return err
	}
	raw, err = b.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "proofs-bad/pk-length-under-own-id.bundle"), raw, 0o644); err != nil {
		return err
	}

	// This tree needs no new fixture-log entry. Its second leaf is an enroll
	// carrying a canonical order-8 key. The log and witnesses sign its real root.
	raw, err = os.ReadFile(filepath.Join(root, "proofs/nas.bundle"))
	if err != nil {
		return err
	}
	sound, err := proof.Decode(raw)
	if err != nil {
		return err
	}
	env, err := entry.Decode(sound.Entry)
	if err != nil {
		return err
	}
	request := mustMap(env.Body["request"].([]byte))
	request["device_pk"] = []byte{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05}
	requestRaw, err := cbor.Encode(request)
	if err != nil {
		return err
	}
	env.Body["request"] = requestRaw
	env.Sigs = nil
	for _, name := range []string{"signer1", "signer2", "signer3"} {
		signer, err := seedKey(root, name)
		if err != nil {
			return err
		}
		if err := entry.Sign(env, signer, "signer"); err != nil {
			return err
		}
	}
	bad, err := entry.Encode(env)
	if err != nil {
		return err
	}
	small := [][]byte{sound.Entry, bad}
	head, err := signedHeadOver(root, origin, key, small, signers)
	if err != nil {
		return err
	}
	tree, err = tlog.Build(small)
	if err != nil {
		return err
	}
	path, err = tree.InclusionProof(1)
	if err != nil {
		return err
	}
	b, err = proof.Build(request["device_id"].(string), 1, bad, path, head)
	if err != nil {
		return err
	}
	raw, err = b.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "proofs-bad/request-device-pk-small-order.bundle"), raw, 0o644); err != nil {
		return err
	}
	return extendRunFourteenManifest(root, "proofs-bad", []map[string]string{
		{"name": "short-proof-hash", "says": "32-byte string"},
		{"name": "request-device-pk-small-order", "says": "request does not decode"},
		{"name": "pk-length-under-own-id", "says": "request does not decode"},
	}, map[string]string{"short-proof-hash": "bundle", "request-device-pk-small-order": "binding", "pk-length-under-own-id": "binding"}, map[string]map[string]string{
		"short-proof-hash":              {"section": "10.1", "says": "or a `proof` element that is not exactly 32 bytes, as §8.1 types it"},
		"request-device-pk-small-order": {"section": "10.1", "says": "an `enroll` whose request does not decode"},
		"pk-length-under-own-id":        {"section": "10.1", "says": "an `enroll` whose request does not decode"},
	}, false)
}

// Retain the exact signed text and surviving lines. Removing corroboration
// does not change the log's signature or any witness signature that remains.
func runSeventeenWithoutWitnesses(head string, remove map[string]bool) string {
	text, block, _ := strings.Cut(head, "\n\n")
	lines := []string{}
	for _, line := range strings.Split(block, "\n") {
		if line == "" {
			continue
		}
		skip := false
		for name := range remove {
			skip = skip || strings.HasPrefix(line, note.SigPrefix+"norn-witness/"+name+" ")
		}
		if !skip {
			lines = append(lines, line)
		}
	}
	return text + "\n\n" + strings.Join(lines, "\n") + "\n"
}

func writeReplayedPolicy(root string) error {
	dir := filepath.Join(root, "replayed-policy")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(root, "fork/evidence.cbor"))
	if err != nil {
		return err
	}
	ev, err := forkevidence.Parse(raw)
	if err != nil {
		return err
	}
	ev.Held = runSeventeenWithoutWitnesses(ev.Held, map[string]bool{"friend": true})
	ev.Conflicting = runSeventeenWithoutWitnesses(ev.Conflicting, map[string]bool{"friend": true})
	raw, err = ev.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence.cbor"), raw, 0o644); err != nil {
		return err
	}
	raw, err = os.ReadFile(filepath.Join(root, "proofs/nas.bundle"))
	if err != nil {
		return err
	}
	b, err := proof.Decode(raw)
	if err != nil {
		return err
	}
	b.Checkpoint = runSeventeenWithoutWitnesses(b.Checkpoint, map[string]bool{"friend": true})
	raw, err = b.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "nas.bundle"), raw, 0o644); err != nil {
		return err
	}
	return writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"trust": "../trust.cbor", "replay": "../served",
		"readers": map[string]string{"fresh": "trust.cbor only; two of three", "informed": "replayed served; roots published three of three"},
		"cases": []map[string]string{
			{"name": "evidence-fresh", "file": "evidence.cbor", "reader": "fresh", "says": "pi and vps prove the fork under the trust policy"},
			{"name": "evidence-informed", "file": "evidence.cbor", "reader": "informed", "says": "held lacks the replayed quorum"},
			{"name": "bundle-fresh", "file": "nas.bundle", "reader": "fresh", "says": "pi and vps satisfy the trust policy"},
			{"name": "bundle-informed", "file": "nas.bundle", "reader": "informed", "says": "the bundle lacks the replayed quorum"},
		},
		"codes": map[string]string{"evidence-fresh": "accept", "evidence-informed": "held", "bundle-fresh": "accept", "bundle-informed": "quorum"},
		"rules": map[string]map[string]string{
			"evidence-fresh":    {"section": "9.4", "says": "A node holding only the trust file uses its policy."},
			"bundle-fresh":      {"section": "9.4", "says": "A node holding only the trust file uses its policy."},
			"evidence-informed": {"section": "11.1", "says": "The reader uses **its own** policy: the trust file's, or one it has replayed (§9.4)."},
			"bundle-informed":   {"section": "8.1", "says": "log_key` of a state it has accepted) and the policy of that state"},
		},
		"comment": "Only friend's lines are removed from fork/evidence.cbor and proofs/nas.bundle. Both original files accept for both readers; replay served under the trust policy before checking these artifacts. accept for evidence means fork proved.",
	})
}

func writeQuorumNone(root, signed string, entries [][]byte) error {
	dir := filepath.Join(root, "quorum-none")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		return err
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		return err
	}
	doc.Policy = strings.Replace(doc.Policy, "quorum home\n", "quorum none\n", 1)
	if !strings.Contains(doc.Policy, "quorum none\n") {
		return fmt.Errorf("fixture policy has no quorum home")
	}
	raw, err = doc.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "trust.cbor"), raw, 0o644); err != nil {
		return err
	}
	head := runSeventeenWithoutWitnesses(signed, map[string]bool{"pi": true, "vps": true, "friend": true})
	if err := os.WriteFile(filepath.Join(dir, "uncosigned.checkpoint"), []byte(head), 0o644); err != nil {
		return err
	}
	ids := proven.Devices(replay.Replay(replay.FromTrust(doc), entries), time.Time{})
	return writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"trust": "trust.cbor", "serve_over": "served",
		"cases": []map[string]any{
			{"name": "uncosigned", "file": "uncosigned.checkpoint", "proven": ids, "says": "quorum none accepts without cosignatures and supplies no clock"},
			{"name": "cosigned-no-clock", "file": "../served/checkpoint", "proven": ids, "says": "quorum none supplies no clock even when witnesses signed; contractor remains proven"},
		},
		"codes": map[string]string{"uncosigned": "accept", "cosigned-no-clock": "accept"},
		"rules": map[string]map[string]string{
			"uncosigned":        {"section": "9.1", "says": "it names a witness, a group, or the reserved name `none`."},
			"cosigned-no-clock": {"section": "13", "says": "With no quorum time, expiry cannot be judged and active claims retain their"},
		},
		"comment": "The trust file differs only in its quorum directive and retains all witnesses. Serve each head over served's unchanged tiles. Both have no quorum time; expected proven is the active set including contractor. Substituting a wall clock past contractor's expires drops it.",
	})
}

func writeGenesisUnapplied(root, origin string, key ed25519.PrivateKey, entries [][]byte, signers []cosignpkg.Signer) error {
	env, err := entry.Decode(entries[0])
	if err != nil {
		return err
	}
	if len(env.Sigs) != 2 {
		return fmt.Errorf("fixture genesis must carry two root signatures")
	}
	env.Sigs = env.Sigs[:1]
	raw, err := entry.Encode(env)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "genesis-unapplied")
	if _, err := serveInto(dir, origin, key, [][]byte{raw}, signers); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "entry.cbor"), raw, 0o644); err != nil {
		return err
	}
	trustRaw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		return err
	}
	doc, err := trust.Parse(trustRaw)
	if err != nil {
		return err
	}
	doc.GenesisHash = entry.LeafHash(raw)
	trustRaw, err = doc.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "trust.cbor"), trustRaw, 0o644); err != nil {
		return err
	}
	if _, err := serveInto(filepath.Join(dir, "sound"), origin, key, entries[:1], signers); err != nil {
		return err
	}
	return writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"cases": []map[string]any{
			{"name": "unapplied", "serve": ".", "trust": "trust.cbor", "proven": []string{}, "says": "the pinned entry 0 has only one of its required two root signatures"},
			{"name": "sound", "serve": "sound", "trust": "../trust.cbor", "proven": []string{}, "says": "the unchanged fixture genesis applies with both root signatures"},
		},
		"codes": map[string]string{"unapplied": "genesis", "sound": "accept"},
		"rules": map[string]map[string]string{
			"unapplied": {"section": "10.1", "says": "replaying it alone aborts with `bad-genesis` (§5.1)."},
			"sound":     {"section": "10.1", "says": "replaying it alone aborts with `bad-genesis` (§5.1)."},
		},
		"comment": "A reader holding no checkpoint checks each one-entry log under the named trust. The bad anchor pins exactly entry.cbor's leaf hash, but replay aborts bad-genesis: matching the leaf hash alone would accept an empty proven set. sound restores the removed signature and the original trust hash.",
	})
}
