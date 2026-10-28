package logclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/ed25519v1"
	"github.com/onembyte/norn/internal/note"
)

// A single separator LF followed directly by a signature line isolates empty
// text: no checkpoint body can be misread as a malformed signature block.
func checkEmptySignedTextCheckpoint(t *testing.T) {
	t.Helper()
	const name = "49-empty-signed-text"
	var manifest struct {
		Cases []string
		Codes map[string]string
		Rules map[string]struct{ Section, Says string }
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", "cases.json"))), &manifest); err != nil {
		t.Fatal(err)
	}
	listed := 0
	for i, c := range manifest.Cases {
		if i > 0 && c <= manifest.Cases[i-1] {
			t.Fatal("cases must remain in number order")
		}
		if c == name {
			listed++
		}
	}
	if listed != 1 || manifest.Codes[name] != "note" || manifest.Rules[name].Section != "7" || manifest.Rules[name].Says != "The text is at least one" {
		t.Fatal("missing 49-empty-signed-text note case and nonempty-text rule")
	}
	head := readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", name+".checkpoint"))
	if len(head) < 2 || head[0] != '\n' || head[1] == '\n' {
		t.Fatal("must have exactly one separator LF before the framed signature")
	}
	// Supply a temporary text line only to parse the signature block. Verify
	// its signature over the original empty bytes, not that temporary line.
	_, sigs, err := note.Split("probe\n" + head)
	if err != nil || len(sigs) != 1 {
		t.Fatalf("signature block must frame: %v", err)
	}
	anchor := shippedLogAnchor(t)
	verifier, err := note.ParseVerifierKey(anchor.LogKeys[0])
	if err != nil {
		t.Fatal(err)
	}
	sig := sigs[0]
	if sig.Name != verifier.Name || !bytes.Equal(sig.KeyID, verifier.ID()) || !ed25519v1.Verify(verifier.Public, nil, sig.Sig) {
		t.Fatal("must carry a genuine matched log signature over empty text")
	}
	if head != "\n"+note.SignatureLine(verifier.Name, append(verifier.ID(), sig.Sig...))+"\n" {
		t.Fatal("empty text and one framed signature must be the whole note")
	}
	if head != readFile(t, filepath.Join(vectorRoot(), "receipt-bad", "empty-signed-text.note")) {
		t.Fatal("checkpoint and receipt siblings must exercise the same note bytes")
	}
	seed := sha256.Sum256([]byte("norn/testvector/v1\nlogkey"))
	key := ed25519.NewKeyFromSeed(seed[:])
	if _, err := note.Sign("", verifier.Name, key); err == nil {
		t.Fatal("the signer must refuse empty text")
	}
	honest := filepath.Join(vectorRoot(), "served")
	base := readFile(t, filepath.Join(honest, "checkpoint"))
	text, lines, err := note.Split(base)
	if err != nil {
		t.Fatal(err)
	}
	repaired, err := note.Sign(text, verifier.Name, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range lines {
		if line.Name == verifier.Name && bytes.Equal(line.KeyID, verifier.ID()) {
			continue
		}
		repaired += note.SignatureLine(line.Name, append(bytes.Clone(line.KeyID), line.Sig...)) + "\n"
	}
	if repaired != base {
		t.Fatal("restoring checkpoint text and renewing its log signature must recover the honest head")
	}
	if _, err := Verify(Dir(servedWith(t, honest, repaired)), anchor); err != nil {
		t.Fatalf("empty-text repair: %v", err)
	}
	t.Log("framed log signature verifies over empty text; repaired checkpoint text and renewed signature accepted")
}
