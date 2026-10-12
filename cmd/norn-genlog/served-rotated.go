// These vectors write the served-rotated directory.

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/state"
)

// writeRotatedHead ships §9.4's rotation case: the same head, signed by a key
// the log's roots published rather than by the one the trust file names.
//
// It was the suite's first vector with two correct answers, and which one is
// right depends on what the reader has done rather than on what the file contains: a
// node holding only `trust.cbor` must refuse it, and a node that has replayed
// this log -- and so learned the key -- must accept it. That is the whole of
// D-020, and nothing in the suite expressed it.
func writeRotatedHead(root, origin, signed string, st *state.State,
	signers []cosignpkg.Signer) error {

	if len(st.LogKeys) == 0 {
		return fmt.Errorf("the fixture publishes no log_key entry to rotate to")
	}
	raw, err := hex.DecodeString(st.LogKeys[0].Pk)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("the first published log key is not a 32-byte key")
	}
	key, err := seedKeyForPublic(root, raw)
	if err != nil {
		return err
	}

	body, err := noteBody(signed)
	if err != nil {
		return err
	}
	head, err := note.Sign(body, origin, key)
	if err != nil {
		return err
	}
	head, err = staggeredCosigner(signers)(head)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-rotated")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
		return err
	}
	meta := map[string]any{
		"serve_over":  "served",
		"signed_by":   st.LogKeys[0].Pk,
		"since_index": st.LogKeys[0].SinceIndex,
		"overlap":     st.LogKeys[0].Overlap,
		// Cold gate run 13, D16: the answers, stated rather than described, and
		// the third one §12.1 claimed and nothing asked -- a reader that has
		// replayed the rotation still reads the head the log is serving, because
		// the anchor key is kept alongside (§9.4). A reader that replaced it
		// with the learned key passed every case until this field.
		"fresh":                 "log-signature",
		"informed":              "accept",
		"informed_reads_served": "accept",
		"comment": "the served head, signed by the first log key this log's roots " +
			"published (SPEC 9.4). Serve it in place of served/checkpoint over the same " +
			"tiles. A reader holding only trust.cbor (`fresh`) MUST refuse it as " +
			"log-signature: it has never seen the rotation. A reader that has replayed " +
			"this log (`informed`) MUST accept it -- and MUST still accept " +
			"served/checkpoint itself (`informed_reads_served`), because the anchor key " +
			"is kept alongside the learned one, never replaced. The answers are all " +
			"correct, and which applies depends on what the reader has done rather " +
			"than on anything in the file",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

// seedKeyForPublic finds the private key in keys.json whose public half is
// this one.
func seedKeyForPublic(root string, public []byte) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(root, "keys.json"))
	if err != nil {
		return nil, err
	}
	var keys struct {
		Ed25519 map[string]struct{ Seed, Public string } `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, err
	}
	want := hex.EncodeToString(public)
	for _, k := range keys.Ed25519 {
		if k.Public != want {
			continue
		}
		seed, err := hex.DecodeString(k.Seed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("keys.json has no usable seed for %s", want)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	return nil, fmt.Errorf("keys.json holds no private key for the published %s", want)
}
