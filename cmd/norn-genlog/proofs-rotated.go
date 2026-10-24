// These vectors write the proofs-rotated directory.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/refusal"
)

// writeRotatedBundle ships §8.1's rotated case (D-074 (a)): `nas`'s bundle
// with its checkpoint replaced by served-rotated's -- the same head, signed by
// the key the roots published -- which is the bundle a log makes once the
// overlap has passed. Like served-rotated/ it has two correct answers: a
// reader holding only trust.cbor refuses it as `log-signature`, and one that
// trusts the published key, having replayed the rotation, accepts it. A later
// trust file for the same network still names its initial key (D-082 (2)).
func writeRotatedBundle(root string) error {
	raw, err := os.ReadFile(filepath.Join(root, "proofs", "nas.bundle"))
	if err != nil {
		return err
	}
	bundle, err := proof.Decode(raw)
	if err != nil {
		return err
	}
	head, err := os.ReadFile(filepath.Join(root, "served-rotated", "checkpoint"))
	if err != nil {
		return err
	}
	var rotated struct {
		SignedBy   string `json:"signed_by"`
		SinceIndex uint64 `json:"since_index"`
	}
	meta, err := os.ReadFile(filepath.Join(root, "served-rotated", "cases.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(meta, &rotated); err != nil {
		return err
	}
	bundle.Checkpoint = string(head)
	encoded, err := bundle.Encode()
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "proofs-rotated")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "nas.bundle"), encoded, 0o644); err != nil {
		return err
	}
	cases := map[string]any{
		"bundle":      "nas.bundle",
		"signed_by":   rotated.SignedBy,
		"since_index": rotated.SinceIndex,
		"fresh":       refusal.LogSignature,
		"informed":    "accept",
		"comment": "proofs/nas.bundle with its checkpoint replaced by served-rotated's: the " +
			"same head, signed by the log key the roots published at since_index (SPEC 9.4). " +
			"A reader holding only trust.cbor MUST refuse it as `fresh` says; a reader that " +
			"trusts the published key -- it replayed the rotation -- MUST accept it " +
			"(SPEC 8, 8.1, D-074 (a), D-082 (2)). Both answers are correct",
		"rules": map[string]map[string]string{
			"informed": {"section": "8", "says": "reader that has replayed the log through the rotation; one holding only"},
		},
	}
	blob, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}
