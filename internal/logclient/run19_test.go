package logclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
)

// Run 19's suffixes leave every signed byte and expected hash intact. Their
// repairs remove only the suffix, so an earlier fault cannot mask the rule.
func checkRunNineteenWitnessPayload(t *testing.T) {
	t.Helper()
	const name = "48-witness-payload-too-long"
	var manifest struct {
		Cases []string
		Codes map[string]refusal.Code
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", "cases.json"))), &manifest); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range manifest.Cases {
		if c == name {
			found = true
		}
	}
	if !found || manifest.Codes[name] != refusal.Cosignature {
		t.Fatal("missing 48-witness-payload-too-long cosignature case")
	}
	// The cosign package guards the exact payload and its suffix-only repair.
	// Here the repaired note must also survive the complete served-log walker.
	head := readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", name+".checkpoint"))
	honest := readFile(t, filepath.Join(vectorRoot(), "served", "checkpoint"))
	if len(head) <= len(honest) || head[:len(honest)] != honest {
		t.Fatal("the honest head and its lines must remain intact")
	}
	line, err := repairRunNineteenPayload(head[len(honest):])
	if err != nil {
		t.Fatal(err)
	}
	repaired := honest + line
	if _, err := Verify(Dir(servedWith(t, filepath.Join(vectorRoot(), "served"), repaired)), shippedLogAnchor(t)); err != nil {
		t.Fatalf("suffix-only repair: %v", err)
	}
	t.Log("suffix-only cosignature repair accepted")
}

func checkRunNineteenPartialTile(t *testing.T) {
	t.Helper()
	const name = "partial-hash-tile-trailing-bytes"
	cases, codes, serveOver := servedNegatives(t)
	for _, c := range cases {
		if c.Name != name {
			continue
		}
		if serveOver != "served-large" || c.Path != "tile/0/001.p/44" || c.File != name+".bin" || c.Remove || len(c.Files) != 0 || codes[name] != refusal.Tiles {
			t.Fatalf("wrong partial-tile overlay: %+v over %s, code %s", c, serveOver, codes[name])
		}
		good := []byte(readFile(t, filepath.Join(vectorRoot(), serveOver, filepath.FromSlash(c.Path))))
		bad := []byte(readFile(t, filepath.Join(vectorRoot(), "served-bad", c.File)))
		if len(good) != 32*44 || len(bad) != len(good)+2 || !bytes.Equal(bad[:len(good)], good) {
			t.Fatal("all 44 hashes must match, with exactly two bytes after them")
		}
		dir := c.apply(t, serveOver)
		write(t, filepath.Join(dir, filepath.FromSlash(c.Path)), string(bad[:len(bad)-2]))
		if _, err := Verify(Dir(dir), shippedLogAnchor(t)); err != nil {
			t.Fatalf("suffix-only repair: %v", err)
		}
		t.Log("suffix-only partial-tile repair accepted")
		return
	}
	t.Fatal("missing partial-hash-tile-trailing-bytes case")
}

func repairRunNineteenPayload(line string) (string, error) {
	name, blob, ok := strings.Cut(strings.TrimSuffix(strings.TrimPrefix(line, note.SigPrefix), "\n"), " ")
	payload, err := base64.StdEncoding.DecodeString(blob)
	if !ok || err != nil || name != "norn-witness/pi" || len(payload) != 77 {
		return "", fmt.Errorf("expected one 77-byte pi line")
	}
	return note.SignatureLine(name, payload[:76]) + "\n", nil
}
