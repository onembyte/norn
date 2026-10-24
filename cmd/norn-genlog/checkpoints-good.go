// These positives pin the inclusive note-number bounds without growing log/.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
)

func writeGoodCheckpoints(root, signed string, signers []cosignpkg.Signer) error {
	dir := filepath.Join(root, "checkpoints-good")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	body := mustBody(signed)
	cappedTime := ""
	for _, signer := range signers {
		if signer.Name == "norn-witness/pi" {
			line, err := cosignpkg.Sign(body, signer.Name, signer.Key, time.Unix(1<<63-1, 0))
			if err != nil {
				return err
			}
			cappedTime = signed + line + "\n"
		}
	}
	if cappedTime == "" {
		return fmt.Errorf("the fixture has no pi witness")
	}
	key, err := seedKey(root, "logkey")
	if err != nil {
		return err
	}
	lines := strings.Split(body, "\n")
	lines[1] = "9223372036854775807"
	cappedSize, err := note.Sign(strings.Join(lines, "\n"), lines[0], key)
	if err != nil {
		return err
	}
	cappedSize, err = staggeredCosigner(signers)(cappedSize)
	if err != nil {
		return err
	}
	for name, head := range map[string]string{"cosignature-time-at-the-cap": cappedTime, "size-at-the-cap": cappedSize} {
		if err := os.WriteFile(filepath.Join(dir, name+".checkpoint"), []byte(head), 0o644); err != nil {
			return err
		}
	}
	return writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"cases": []map[string]string{
			{"name": "cosignature-time-at-the-cap", "file": "cosignature-time-at-the-cap.checkpoint", "layer": "served", "serve_over": "../served", "says": "at most 2⁶³−1"},
			{"name": "size-at-the-cap", "file": "size-at-the-cap.checkpoint", "layer": "checkpoint", "says": "at most 2⁶³−1"},
		},
		"codes": map[string]string{"cosignature-time-at-the-cap": "accept", "size-at-the-cap": "accept"},
		"rules": map[string]map[string]string{
			"cosignature-time-at-the-cap": {"section": "7", "says": "at most 2⁶³−1"},
			"size-at-the-cap":             {"section": "6", "says": "at most 2⁶³−1"},
		},
		"comment": "The served case adds one pi cosignature at 9223372036854775807 to the unchanged served head. The size case changes only the body size and renews the log signature and all cosignatures; verify it at the checkpoint layer only, never by requesting entries or tiles.",
	})
}
