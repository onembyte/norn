// These vectors pin D-077's timestamp bound and whole signed-note grammar.
package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
)

func writeNoteGrammarCheckpoints(root, signed string, signers []cosignpkg.Signer) error {
	body := mustBody(signed)
	var pi cosignpkg.Signer
	for _, signer := range signers {
		if signer.Name == "norn-witness/pi" {
			pi = signer
		}
	}
	if pi.Key == nil {
		return fmt.Errorf("the fixture has no pi witness")
	}
	const at uint64 = 1 << 63
	payload := note.KeyIDFor(pi.Name, pi.Key.Public().(ed25519.PublicKey), note.AlgCosignature)
	payload = binary.BigEndian.AppendUint64(payload, at)
	// Sign the unsigned decimal, not the negative value the old Go cast used.
	message := fmt.Appendf(nil, "%s\ntime %d\n%s", cosignpkg.Header, at, body)
	payload = append(payload, ed25519.Sign(pi.Key, message)...)
	prefix := note.SigPrefix + pi.Name + " "
	lines := strings.Split(strings.TrimSuffix(signed, "\n"), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			lines[i] = note.SignatureLine(pi.Name, payload)
		}
	}
	cases := []badCheckpoint{{"38-cosignature-time-above-2-63", "a listed witness re-cosigns the honest head at 9223372036854775808", strings.Join(lines, "\n") + "\n"}}
	// Each extra line is otherwise a canonical 68-byte frame. Repairing only
	// its name leaves the same ignored payload beside every honest signature.
	for _, c := range []struct{ name, stranger string }{
		{"39-signature-name-empty", ""},
		{"40-signature-name-tab", "stranger\tname"},
		{"41-signature-name-nbsp", "stranger\u00a0name"},
		{"42-signature-name-plus", "stranger+name"},
		{"43-signature-name-nul", "stranger\x00name"},
	} {
		cases = append(cases, badCheckpoint{c.name, "an otherwise honest head with a malformed stranger name", signed + note.SignatureLine(c.stranger, make([]byte, 68)) + "\n"})
	}
	crBody := strings.TrimSuffix(body, "\n") + "\r\n"
	key, err := seedKey(root, "logkey")
	if err != nil {
		return err
	}
	origin := strings.SplitN(body, "\n", 2)[0]
	crHead, err := note.Sign(crBody, origin, key)
	if err != nil {
		return err
	}
	// Append frames the note before cosigning and therefore refuses this body.
	// Sign the exact malformed bytes directly, in the honest head's order and
	// at its timestamps, so only the framing rule supplies the note refusal.
	for i, signer := range signers {
		line, err := cosignpkg.Sign(crBody, signer.Name, signer.Key, time.Unix(CosignedAt+int64(i*CosignSpread), 0))
		if err != nil {
			return err
		}
		crHead += line + "\n"
	}
	cases = append(cases, badCheckpoint{"44-carriage-return-in-signed-text", "the honest body with one CR before the root line's LF, signed and cosigned over those exact bytes", crHead})
	listed := make([]map[string]string, 0, len(cases))
	codes := map[string]string{}
	rules := map[string]map[string]string{}
	for i, c := range cases {
		if err := os.WriteFile(filepath.Join(root, "checkpoints-bad", c.Name+".checkpoint"), []byte(c.Signed), 0o644); err != nil {
			return err
		}
		listed = append(listed, map[string]string{"name": c.Name, "says": c.Reason})
		codes[c.Name] = "note"
		rules[c.Name] = map[string]string{"section": "7", "says": "**A signature line's name** is one or more characters, none of them `+`"}
		if i == 0 {
			codes[c.Name] = "cosignature"
			rules[c.Name]["section"] = "10.1"
			rules[c.Name]["says"] = "whose timestamp is above 2⁶³−1 (§7, D-077)"
		}
		if i == 5 || c.Name == "44-carriage-return-in-signed-text" {
			rules[c.Name]["says"] = "MUST NOT contain an ASCII control character below U+0020"
		}
	}
	return extendRunFourteenManifest(root, "checkpoints-bad", listed, codes, rules, true)
}

// Signature-blind means no Ed25519 check, while framing, matched lengths and
// the timestamp bound still hold. Recompute after all manifest extensions so
// a new case cannot silently change this claim.
func signatureBlindCheckpoints(root string, names []string) ([]string, error) {
	honest, err := os.ReadFile(filepath.Join(root, "served", "checkpoint"))
	if err != nil {
		return nil, err
	}
	body, _, err := note.Split(string(honest))
	if err != nil {
		return nil, err
	}
	rules, err := policy.Parse(policyOf(root))
	if err != nil {
		return nil, err
	}
	// The honest note's log key comes from the same published trust anchor.
	logPublic, err := seedKey(root, "logkey")
	if err != nil {
		return nil, err
	}
	origin := strings.SplitN(body, "\n", 2)[0]
	logKey, err := note.ParseVerifierKey(note.VerifierKey(origin, logPublic.Public().(ed25519.PublicKey)))
	if err != nil {
		return nil, err
	}
	trusted := []note.Verifier{logKey}
	for _, key := range rules.Keys() {
		v, err := note.ParseVerifierKey(key)
		if err != nil {
			return nil, err
		}
		trusted = append(trusted, v)
	}
	blind := []string{}
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(root, "checkpoints-bad", name+".checkpoint"))
		if err != nil {
			return nil, err
		}
		text, sigs, err := note.Split(string(raw))
		if err != nil || text != body {
			continue
		}
		valid, logMatched := true, false
		var labels []string
		for _, sig := range sigs {
			for _, v := range trusted {
				if sig.Name != v.Name || string(sig.KeyID) != string(v.ID()) {
					continue
				}
				if v.IsCosigner() {
					if !sig.IsCosignature() || binary.BigEndian.Uint64(sig.Sig[:8]) > 1<<63-1 {
						valid = false
						continue
					}
					labels = append(labels, rules.Label(sig.Name))
				} else {
					if len(sig.Sig) != ed25519.SignatureSize {
						valid = false
					}
					logMatched = true
				}
			}
		}
		if valid && logMatched && rules.Satisfied(labels) {
			blind = append(blind, name)
		}
	}
	return blind, nil
}
