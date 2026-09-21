package note

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Cold-model gate run 10, defect D13 ---------------------------------
//
// §7 restates `c2sp.org/signed-note` "so an implementer needs nothing else",
// and left five splits undecided. Each of these variants passed all 236
// checks: split a signature line on its **last** space; accept **unpadded**
// base64; accept a payload **longer** than 68 or 76 bytes and verify the
// prefix; end the text at the **last** blank line; and require no signature
// line at all.
//
// `V206` is the one with teeth. Accepting a longer payload means a checkpoint
// has unboundedly many byte-distinct forms that all verify — so two nodes
// gossiping the same head disagree about its bytes, and any rule keyed on
// them (a cache, a de-duplication set, an anchor over the body) is keyed on
// something the attacker chooses.
//
// The three that a file can separate get one here. Each is the honest
// checkpoint with one line rewritten, so the framing rule is the whole fault:
// the test proves that by decoding the line the lax way and finding a
// signature that verifies.

func badCheckpoint(t *testing.T, suffix string) string {
	t.Helper()
	dir := filepath.Join(vectorRoot(), "checkpoints-bad")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []string `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range doc.Cases {
		if strings.HasSuffix(name, suffix) {
			body, err := os.ReadFile(filepath.Join(dir, name+".checkpoint"))
			if err != nil {
				t.Fatal(err)
			}
			return string(body)
		}
	}
	t.Fatalf("no checkpoints-bad case named *%s", suffix)
	return ""
}

func logVerifier(t *testing.T) Verifier {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		LogKey string `json:"log_vkey"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	if keys.LogKey == "" {
		t.Skip("keys.json carries no log verifier key under `log_vkey`")
	}
	v, err := ParseVerifierKey(keys.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// lastSignatureLine returns the final `— …` line of a signed note, without its
// newline.
func lastSignatureLine(t *testing.T, signed string) string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], SigPrefix) {
			return lines[i]
		}
	}
	t.Fatal("the note carries no signature line")
	return ""
}

// D13, V202. A key name contains no space, so a signature line splits at its
// **first** one. Split it at the last instead and this note's extra line is a
// well-formed signature from a name nobody lists — ignored, not refused, so
// the checkpoint is accepted.
func TestASignatureLineSplitsAtItsFirstSpace(t *testing.T) {
	signed := badCheckpoint(t, "-signature-name-with-space")
	if _, _, err := Split(signed); err == nil {
		t.Fatal("accepted a signature line whose name contains a space")
	}

	line := strings.TrimPrefix(lastSignatureLine(t, signed), SigPrefix)
	name, blob, ok := strings.Cut(line, " ")
	if !ok {
		t.Fatal("the line has no space at all")
	}
	if !strings.Contains(blob, " ") {
		t.Fatalf("the name %q is followed by no second space, so the two readings "+
			"cannot disagree about this line", name)
	}
	// The lax reading: everything before the last space is the name.
	at := strings.LastIndex(line, " ")
	raw, err := base64.StdEncoding.DecodeString(line[at+1:])
	if err != nil {
		t.Fatalf("splitting at the last space does not yield base64 (%v), so the "+
			"vector is refused for something other than where the split falls", err)
	}
	if len(raw) != 4+ed25519.SignatureSize && len(raw) != 4+8+ed25519.SignatureSize {
		t.Errorf("the lax reading yields a %d-byte payload; it must be a well-formed "+
			"one, or a reader splitting at the last space refuses this note anyway",
			len(raw))
	}
}

// D13, V204. The base64 is standard **with padding**. Strip the padding and a
// raw-base64 reader decodes the same bytes and verifies the same signature.
func TestASignaturePayloadIsPaddedBase64(t *testing.T) {
	signed := badCheckpoint(t, "-signature-unpadded-base64")
	if _, _, err := Split(signed); err == nil {
		t.Fatal("accepted an unpadded signature payload")
	}

	line := strings.TrimPrefix(lastSignatureLine(t, signed), SigPrefix)
	_, blob, _ := strings.Cut(line, " ")
	if strings.HasSuffix(blob, "=") {
		t.Fatal("the payload still carries its padding, so the vector is about nothing")
	}
	raw, err := base64.RawStdEncoding.DecodeString(blob)
	if err != nil {
		t.Fatalf("the payload is not raw base64 either (%v), so it is refused for "+
			"being unreadable rather than for being unpadded", err)
	}
	if len(raw) != 4+ed25519.SignatureSize && len(raw) != 4+8+ed25519.SignatureSize {
		t.Errorf("the raw reading yields %d bytes, which is neither of §7's two "+
			"payload lengths, so the line is refused for its length rather than "+
			"for its padding", len(raw))
	}
}

// D13, V206. The decoded payload is **exactly** 68 bytes for algorithm 0x01.
// Append one and a prefix-reading verifier still verifies — so the same head
// has unboundedly many byte-distinct forms, every one of them valid.
func TestASignaturePayloadIsExactlyItsAlgorithmsLength(t *testing.T) {
	signed := badCheckpoint(t, "-signature-payload-too-long")
	if _, _, err := Split(signed); err == nil {
		t.Fatal("accepted a signature payload longer than its algorithm's length")
	}

	text, _, _ := strings.Cut(signed, "\n\n")
	text += "\n"
	line := strings.TrimPrefix(lastSignatureLine(t, signed), SigPrefix)
	_, blob, _ := strings.Cut(line, " ")
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		t.Fatalf("the payload is not base64 (%v); the length must be the only fault", err)
	}
	if len(raw) <= 4+ed25519.SignatureSize {
		t.Fatalf("the payload is %d bytes; it must be longer than 68 for the prefix "+
			"reading to differ", len(raw))
	}
	v := logVerifier(t)
	if string(raw[:4]) != string(v.ID()) {
		t.Fatal("the line does not name the log's key id, so §10 would ignore it and " +
			"the length rule is never reached")
	}
	if !ed25519.Verify(v.Public, []byte(text), raw[4:4+ed25519.SignatureSize]) {
		t.Error("the first 68 bytes are not a valid signature over the text, so a " +
			"prefix-reading verifier refuses this note anyway and the exact-length " +
			"rule is pinned by nothing")
	}
}
