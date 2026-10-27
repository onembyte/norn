package cosign

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
)

// A valid 76-byte prefix does not excuse a suffix under a listed witness's
// name and key id. The existing honest lines still make the quorum.
func TestAListedWitnessPayloadMustEndAtSeventySixBytes(t *testing.T) {
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(vectorRoot(), path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	honest := read("served/checkpoint")
	bad := read("checkpoints-bad/48-witness-payload-too-long.checkpoint")
	if !bytes.HasPrefix(bad, honest) {
		t.Fatal("the honest log and witness lines changed")
	}
	extra := strings.TrimSuffix(string(bad[len(honest):]), "\n")
	if strings.Contains(extra, "\n") {
		t.Fatal("expected exactly one added line")
	}
	name, blob, ok := strings.Cut(strings.TrimPrefix(extra, note.SigPrefix), " ")
	payload, err := base64.StdEncoding.DecodeString(blob)
	if !ok || err != nil || name != "norn-witness/pi" || len(payload) != 77 {
		t.Fatal("expected a 77-byte pi payload")
	}
	_, sigs, err := note.Split(string(honest))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sig := range sigs {
		if sig.Name == name {
			found = bytes.Equal(payload[:4], sig.KeyID) && bytes.Equal(payload[4:76], sig.Sig)
		}
	}
	if !found {
		t.Fatal("the first 76 bytes must be pi's genuine payload, including its key id")
	}
	t.Run("the suffix is refused", func(t *testing.T) {
		_, err := Verify(string(bad), witnessKeys(t))
		if code, _ := refusal.CodeOf(err); code != refusal.Cosignature {
			t.Fatalf("got %s, %v; want cosignature", code, err)
		}
	})
	t.Run("removing only the suffix accepts", func(t *testing.T) {
		repaired := string(honest) + note.SignatureLine(name, payload[:76]) + "\n"
		valid, err := Verify(repaired, witnessKeys(t))
		if err != nil || len(valid) != 4 {
			t.Fatalf("suffix-only repair: %d lines, %v", len(valid), err)
		}
		t.Log("suffix-only cosignature repair accepted with all four witness lines")
	})
}
