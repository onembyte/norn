// These vectors write the served-superseded directory.

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
)

// writeSupersededHead ships §9.4's policy case: the served head cosigned by
// exactly two witnesses.
//
// The fixture's roots raise the quorum from two of three to three of three.
// A fresh reader accepts under trust; the informed reader already verified
// served/ and holds this same tree. D-082 (1) keeps its acceptance and T,
// even though this note omits a line. A larger head would face the new quorum.
func writeSupersededHead(root, origin, signed string, key ed25519.PrivateKey,
	signers []cosignpkg.Signer) error {

	if len(signers) < 3 {
		return fmt.Errorf("the fixture has %d witnesses; this case needs three", len(signers))
	}
	body, err := noteBody(signed)
	if err != nil {
		return err
	}
	head, err := note.Sign(body, origin, key)
	if err != nil {
		return err
	}
	head, err = staggeredCosigner(signers[:2])(head)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-superseded")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
		return err
	}
	// Keep pi's name and key id, changing only the last signature byte. The
	// held head's evidence survives, but this copy must refuse (D-084 (1)).
	lines := strings.Split(signed, "\n")
	forged := false
	for i, line := range lines {
		name, blob, ok := strings.Cut(strings.TrimPrefix(line, "— "), " ")
		if !strings.HasPrefix(line, "— ") || !ok || !strings.HasSuffix(name, "/pi") {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			return err
		}
		payload[len(payload)-1] ^= 0x01
		lines[i] = "— " + name + " " + base64.StdEncoding.EncodeToString(payload)
		forged = true
		break
	}
	if !forged {
		return fmt.Errorf("the served checkpoint has no pi cosignature")
	}
	if err := os.WriteFile(filepath.Join(dir, "forged-pi.checkpoint"), []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return err
	}
	meta := map[string]any{
		"forged_copy": map[string]string{
			"file": "forged-pi.checkpoint", "fresh": "cosignature", "informed": "cosignature",
			"retains": "../served/checkpoint",
		},
		"serve_over":  "served",
		"cosigned_by": []string{signers[0].Name, signers[1].Name},
		"fresh":       "accept",
		"informed":    "accept",
		// The informed reader holds served's three-line note, whose two-of-three
		// acceptance is seven seconds later than this two-line note's would be.
		"informed_quorum_time": QuorumTimeOf(2),
		"comment": "the served head cosigned by two of the three witnesses. A reader " +
			"holding only trust.cbor (`fresh`) requires two and MUST accept it; a reader " +
			"that verified and replayed served/ and holds its head (`informed`) MUST " +
			"accept the same tree and keep its stored policy and T=1760003607, not " +
			"1760003600 (SPEC 5.3, D-082 (1)). Serve it in place of served/checkpoint " +
			"over the same tiles. The raised quorum binds a new head, not a re-read. " +
			"forged-pi.checkpoint is served/checkpoint with the last byte of pi's " +
			"cosignature signature XOR 0x01, keeping its name and key id: both readers " +
			"refuse cosignature, and the informed reader retains served/checkpoint's " +
			"note, cosignatures and T. A re-read checks its own lines without judging " +
			"its quorum again or storing the copy (D-084 (1))",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}
