package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/onembyte/norn/internal/note"
)

// Run 22 adds reader histories and field-only checkpoint variants after the
// existing writers have rebuilt their parents. None changes the served tree.
func writeRunTwentyTwoHeads(root, signed string) error {
	thin := runSeventeenWithoutWitnesses(signed, map[string]bool{"vps": true, "friend": true})
	if err := os.WriteFile(filepath.Join(root, "served-superseded", "one-cosignature.checkpoint"), []byte(thin), 0o644); err != nil {
		return err
	}
	m, err := d080Manifest(root, "served-superseded")
	if err != nil {
		return err
	}
	m["thin_copy"] = map[string]any{"file": "one-cosignature.checkpoint", "fresh": "quorum", "informed": "accept", "informed_quorum_time": QuorumTimeOf(2), "retains": "../served/checkpoint"}
	m["rules"] = map[string]any{"one-cosignature": map[string]string{"section": "5.3", "says": "not judged again and nothing from the copy is stored"}}
	if err := writeRunFourteenJSON(filepath.Join(root, "served-superseded", "cases.json"), m); err != nil {
		return err
	}

	m, err = d080Manifest(root, "served-bad")
	if err != nil {
		return err
	}
	m["cases"] = append(m["cases"].([]any), map[string]any{"name": "missing-full-hash-tile", "path": "tile/0/000", "remove": true, "says": "the first level-zero tile is full at size 300 and is not served"})
	m["codes"].(map[string]any)["missing-full-hash-tile"] = "unserved"
	m["rules"].(map[string]any)["missing-full-hash-tile"] = map[string]string{"section": "10.1", "says": "a hash tile (step 12)"}
	if err := writeRunFourteenJSON(filepath.Join(root, "served-bad", "cases.json"), m); err != nil {
		return err
	}

	// Reuse the field-only forgery made from served's authentic pi line.
	forged, err := os.ReadFile(filepath.Join(root, "served-superseded", "forged-pi.checkpoint"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "quorum-none", "forged-pi.checkpoint"), forged, 0o644); err != nil {
		return err
	}
	m, err = d080Manifest(root, "quorum-none")
	if err != nil {
		return err
	}
	m["cases"] = append(m["cases"].([]any), map[string]string{"name": "forged-pi", "file": "forged-pi.checkpoint", "says": "a listed witness's forged line refuses even under quorum none"})
	m["codes"].(map[string]any)["forged-pi"] = "cosignature"
	m["rules"].(map[string]any)["forged-pi"] = map[string]string{"section": "9.1", "says": "must verify whether or not its quorum reaches that witness"}
	if err := writeRunFourteenJSON(filepath.Join(root, "quorum-none", "cases.json"), m); err != nil {
		return err
	}
	return writeRunTwentyTwoStrangerHeads(root, signed)
}

func writeRunTwentyTwoStrangerHeads(root, signed string) error {
	_, sigs, err := note.Split(signed)
	if err != nil {
		return err
	}
	origin, _, _ := strings.Cut(signed, "\n")
	for _, kind := range []string{"witness", "log"} {
		name := origin
		payload := make([]byte, 68)
		if kind == "witness" {
			name = "norn-witness/pi"
			payload = make([]byte, 76)
			binary.BigEndian.PutUint64(payload[4:12], uint64(CosignedAt+100))
		}
		found := false
		for _, sig := range sigs {
			if sig.Name == name {
				copy(payload, sig.KeyID)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("served checkpoint has no line for %s", name)
		}
		head := signed + note.SigPrefix + strings.ToUpper(name) + " " + base64.StdEncoding.EncodeToString(payload) + "\n"
		dir := filepath.Join(root, "served-upper-"+kind+"-name")
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
			return err
		}
		if err := writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
			"serve_over": "served", "fresh": "accept", "informed": "accept",
			"comment": "The served checkpoint plus one stranger line named " + strings.ToUpper(name) + " under " + name + "'s key id. Removing that line recovers served/checkpoint byte for byte.",
			"rules":   map[string]any{"name-case": map[string]string{"section": "7", "says": "What follows the key id is judged by the trusted key whose name and key id"}},
		}); err != nil {
			return err
		}
	}
	return nil
}
