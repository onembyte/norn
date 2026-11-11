package logclient

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/refusal"
)

// D-084 (1): a re-read of the head a node holds keeps the acceptance it was
// stored with, but the copy's own lines are still checked as §10 checks every
// checkpoint. A line naming a listed witness that does not verify is
// `cosignature`, whatever the stored evidence says (run 20's L1.10, probe P12).
func TestAReReadOfTheHeldHeadRefusesAForgedLineOfAListedWitness(t *testing.T) {
	fresh := shippedLogAnchor(t)
	dir := filepath.Join(vectorRoot(), "served")
	held, err := Verify(Dir(dir), fresh)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Stored, fresh.Held, fresh.StoredResult = &held.Checkpoint, held.Tree, held
	honest := readFile(t, filepath.Join(dir, "checkpoint"))
	forged := forgeWitnessLine(t, honest, "pi")
	for _, incremental := range []bool{false, true} {
		t.Run(map[bool]string{false: "Verify", true: "VerifyFrom"}[incremental], func(t *testing.T) {
			read := func(checkpoint string) error {
				overlay := servedWith(t, dir, checkpoint)
				if incremental {
					_, err := VerifyFrom(held, Dir(overlay), fresh)
					return err
				}
				_, err := Verify(Dir(overlay), fresh)
				return err
			}
			if code, _ := refusal.CodeOf(read(forged)); code != refusal.Cosignature {
				t.Fatalf("forged line on a re-read of the held head: got %q, want cosignature", code)
			}
			if err := read(honest); err != nil {
				t.Fatalf("the unchanged copy of the held head: %v", err)
			}
			t.Log("forged line refused as cosignature; the unchanged copy accepted")
		})
	}
}

// forgeWitnessLine flips the last byte of the named witness's signature, so
// the line still names that witness under its own key id and cannot verify.
func forgeWitnessLine(t *testing.T, signed, witness string) string {
	t.Helper()
	lines := strings.Split(signed, "\n")
	for i, line := range lines {
		name, blob, ok := strings.Cut(strings.TrimPrefix(line, "— "), " ")
		if !strings.HasPrefix(line, "— ") || !ok || !strings.HasSuffix(name, "/"+witness) {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			t.Fatal(err)
		}
		payload[len(payload)-1] ^= 0x01
		lines[i] = "— " + name + " " + base64.StdEncoding.EncodeToString(payload)
		return strings.Join(lines, "\n")
	}
	t.Fatalf("no line for witness %q in the served checkpoint", witness)
	return ""
}
