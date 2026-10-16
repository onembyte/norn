// These vectors ship D-079 without extending the replay fixture or moving
// the stamped checkpoint. Every changed artifact has a sound shipped twin.
package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/tlog"
)

func writeD079(root, origin string, key ed25519.PrivateKey, entries [][]byte, signed string, signers []cosignpkg.Signer) error {
	raw, err := os.ReadFile(filepath.Join(root, "fork", "evidence.cbor"))
	if err != nil {
		return err
	}
	ev, err := forkevidence.Parse(raw)
	if err != nil {
		return err
	}
	// This canonical order-8 point is the witness key log-admission/07
	// carries. Recomputing its verifier id under pi isolates point admission.
	point := ed25519.PublicKey{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05}
	ev.Policy = "witness pi " + note.CosignerVerifierKey("norn-witness/pi", point) + "\nquorum pi\n"
	raw, err = ev.Encode()
	if err != nil {
		return err
	}
	const policyCase = "bad-policy-small-order-key"
	if err := os.WriteFile(filepath.Join(root, "fork", policyCase+".cbor"), raw, 0o644); err != nil {
		return err
	}
	if err := extendRunFourteenManifest(root, "fork", []map[string]string{{"name": policyCase, "says": "not a valid point"}}, map[string]string{policyCase: "policy"}, map[string]map[string]string{policyCase: {"section": "11.1", "says": "or carries a verifier key that is not a valid point (§3.1)"}}, false); err != nil {
		return err
	}

	raw, err = os.ReadFile(filepath.Join(root, "proofs", "nas.bundle"))
	if err != nil {
		return err
	}
	bundle, err := proof.Decode(raw)
	if err != nil {
		return err
	}
	bundle.Device = "NAS"
	raw, err = bundle.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "proofs-bad", "device-not-a-device-id.bundle"), raw, 0o644); err != nil {
		return err
	}
	const index = 79
	if len(entries) != 162 {
		return fmt.Errorf("D-079 needs the unchanged 162-entry fixture, got %d", len(entries))
	}
	tree, err := tlog.Build(entries)
	if err != nil {
		return err
	}
	path, err := tree.InclusionProof(index)
	if err != nil {
		return err
	}
	bundle, err = proof.Build("probe", index, entries[index], path, signed)
	if err != nil {
		return err
	}
	raw, err = bundle.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "proofs-bad", "request-undecodable.bundle"), raw, 0o644); err != nil {
		return err
	}
	if err := extendRunFourteenManifest(root, "proofs-bad", []map[string]string{
		{"name": "device-not-a-device-id", "says": "device:"},
		{"name": "request-undecodable", "says": "request does not decode"},
	}, map[string]string{"device-not-a-device-id": "bundle", "request-undecodable": "binding"}, map[string]map[string]string{
		"device-not-a-device-id": {"section": "10.1", "says": "or a `device` outside §2's grammar"},
		"request-undecodable":    {"section": "10.1", "says": "an `enroll` whose request does not decode"},
	}, false); err != nil {
		return err
	}
	return writeD079GrownLog(root, origin, key, entries, signed, signers)
}

func writeD079GrownLog(root, origin string, key ed25519.PrivateKey, entries [][]byte, signed string, signers []cosignpkg.Signer) error {
	dir := filepath.Join(root, "grown-log")
	grown := append(append([][]byte(nil), entries...), entries...)
	if _, err := serveInto(dir, origin, key, grown, signers); err != nil {
		return err
	}
	// The store has filled and removed the older partial paths. Publish the
	// older head over its grown tiles, exactly as a reader racing log growth sees.
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(signed), 0o644); err != nil {
		return err
	}
	for _, path := range []string{"tile/0/000.p/162", "tile/entries/000.p/162"} {
		if _, err := os.Stat(filepath.Join(dir, path)); !os.IsNotExist(err) {
			return fmt.Errorf("grown log retains partial path %s: %v", path, err)
		}
	}
	tile, err := os.ReadFile(filepath.Join(dir, "tile/0/000"))
	if err != nil {
		return err
	}
	if len(tile) != 256*32 {
		return fmt.Errorf("grown log full tile is %d bytes", len(tile))
	}
	for _, c := range []struct {
		name  string
		index int
	}{{"corrupt-within-prefix", 10}, {"corrupt-beyond-prefix", 200}} {
		changed := append([]byte(nil), tile...)
		changed[c.index*32] ^= 1
		if err := os.WriteFile(filepath.Join(dir, c.name+".bin"), changed, 0o644); err != nil {
			return err
		}
	}
	return writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"serve_over": "grown-log",
		"cases": []map[string]any{
			{"name": "older-head-over-full-tiles", "says": "accept the older signed head using the full tile and bundle"},
			{"name": "full-tile-gone", "path": "tile/0/000", "remove": true, "says": "neither partial nor full hash tile is served"},
			{"name": "full-bundle-gone", "path": "tile/entries/000", "remove": true, "says": "neither partial nor full entry bundle is served"},
			{"name": "corrupt-within-prefix", "path": "tile/0/000", "file": "corrupt-within-prefix.bin", "says": "one changed byte in hash 10 inside the older head's prefix"},
			{"name": "corrupt-beyond-prefix", "path": "tile/0/000", "file": "corrupt-beyond-prefix.bin", "says": "one changed byte in hash 200 beyond the older head's prefix"},
		},
		"codes": map[string]string{"older-head-over-full-tiles": "accept", "full-tile-gone": "unserved", "full-bundle-gone": "unserved", "corrupt-within-prefix": "tiles", "corrupt-beyond-prefix": "accept"},
		"rules": map[string]map[string]string{
			"older-head-over-full-tiles": {"section": "6", "says": "MAY fetch `tile/<L>/<N>` and use its first `W` hashes"},
			"full-tile-gone":             {"section": "10.1", "says": "`unserved` only when neither the partial path nor the full one is served"},
			"full-bundle-gone":           {"section": "10.1", "says": "`unserved` only when neither the partial path nor the full one is served"},
			"corrupt-within-prefix":      {"section": "6", "says": "what it uses is compared with the tree it rebuilt exactly as the partial path would have been"},
			"corrupt-beyond-prefix":      {"section": "6", "says": "MAY fetch `tile/<L>/<N>` and use its first `W` hashes"},
		},
		"comment": "The 162-entry fixture appended twice produces 324 entries, full tiles and deleted width-162 partial paths. The checkpoint is served's unchanged signed and cosigned head at 162. Apply each replacement or deletion over this directory; the case with no mutation accepts it as served.",
	})
}
