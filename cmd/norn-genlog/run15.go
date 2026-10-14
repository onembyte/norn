// These vectors pin run 15's blank-line framing and listed witness checks.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/onembyte/norn/internal/trust"
)

func writeRunFifteen(root, signed string) error {
	// Insert an empty line after the log's line, retaining every signed byte
	// and placing the fault strictly between two existing signature lines.
	text, block, ok := strings.Cut(signed, "\n\n")
	first, rest, framed := strings.Cut(block, "\n")
	if !ok || !framed || !strings.HasPrefix(rest, "— ") {
		return fmt.Errorf("the honest head needs two signature lines")
	}
	const name = "45-blank-line-between-signatures"
	head := text + "\n\n" + first + "\n\n" + rest
	if err := os.WriteFile(filepath.Join(root, "checkpoints-bad", name+".checkpoint"), []byte(head), 0o644); err != nil {
		return err
	}
	if err := extendRunFourteenManifest(root, "checkpoints-bad", []map[string]string{{"name": name, "says": "one empty line between the honest head's first two signature lines"}}, map[string]string{name: "note"}, map[string]map[string]string{name: {"section": "7", "says": "every line after it belongs to the signature block"}}, true); err != nil {
		return err
	}

	// D-078 requires at least one text line. Prepending only one LF leaves
	// every honest byte intact, so removing it restores the accepted head.
	const blankFirst = "46-blank-first-line"
	if err := os.WriteFile(filepath.Join(root, "checkpoints-bad", blankFirst+".checkpoint"), []byte("\n"+signed), 0o644); err != nil {
		return err
	}
	if err := extendRunFourteenManifest(root, "checkpoints-bad", []map[string]string{{"name": blankFirst, "says": "one line feed before the honest head's text makes its first line blank"}}, map[string]string{blankFirst: "note"}, map[string]map[string]string{blankFirst: {"section": "7", "says": "a note whose first line is blank has an empty first text line"}}, true); err != nil {
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
	// Keep all listed witnesses and keys, but have the quorum reach only pi
	// and vps. Friend's line must still verify before that quorum is checked.
	doc.Policy = strings.Replace(doc.Policy, "group home 2 pi vps friend\n", "group home 2 pi vps\n", 1)
	if !strings.Contains(doc.Policy, "group home 2 pi vps\nquorum home\n") {
		return fmt.Errorf("the fixture policy does not have its expected quorum")
	}
	if err := doc.Validate(); err != nil {
		return err
	}
	raw, err = doc.Encode()
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "unreached-witness")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "trust.cbor"), raw, 0o644); err != nil {
		return err
	}
	forged, err := forgeLastSignature(signed, "norn-witness/friend")
	if err != nil {
		return err
	}
	for _, c := range []struct{ file, head string }{{"honest.checkpoint", signed}, {"forged-friend.checkpoint", forged}} {
		if err := os.WriteFile(filepath.Join(dir, c.file), []byte(c.head), 0o644); err != nil {
			return err
		}
	}
	return writeRunFourteenJSON(filepath.Join(dir, "cases.json"), map[string]any{
		"serve_over": "served", "trust": "trust.cbor",
		"cases": []map[string]string{
			{"name": "honest-head", "file": "honest.checkpoint", "says": "all three listed witnesses verify and pi and vps alone meet the quorum"},
			{"name": "forged-friend", "file": "forged-friend.checkpoint", "says": "friend is listed but outside the quorum; its matching line does not verify"},
		},
		"codes": map[string]string{"honest-head": "accept", "forged-friend": "cosignature"},
		"rules": map[string]map[string]string{
			"honest-head":   {"section": "9.1", "says": "MUST parse, and MUST name **exactly** the witnesses `witnesses` lists"},
			"forged-friend": {"section": "10.1", "says": "a cosignature line whose name **and** key id match a listed witness does not verify"},
		},
		"comment": "Serve each checkpoint over served's honest tiles under this directory's trust.cbor. The policy lists pi, vps and friend, but its quorum is 2 of pi and vps alone. Counting is not checking (SPEC 9.1, 10.1).",
	})
}
