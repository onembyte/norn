package proof

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/refusal"
)

func TestABundleAroundNasRotateAcceptsUnderItsOwnLabel(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var m struct {
		Sound []struct {
			Name, File, Device string
			Index              int64
		}
		Codes map[string]string
	}
	if err := json.Unmarshal(read("proofs/cases.json"), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Sound) != 2 || m.Sound[0].Name != "nas-rotate" || m.Sound[0].Device != "nas" || m.Sound[0].Index != 35 || m.Codes["nas-rotate"] != "accept" {
		t.Fatal("proofs manifest must list the nas rotate as sound")
	}
	b, err := Decode(read("proofs/" + m.Sound[0].File))
	if err != nil {
		t.Fatal(err)
	}
	if b.Device != "nas" || b.Index != 35 || !bytes.Equal(b.Entry, read("log/35-rotate-nas.cbor")) {
		t.Fatal("bundle must prove the fixture's real nas rotation")
	}
	env, err := entry.Decode(b.Entry)
	if err != nil || env.T != "rotate" || env.Body["device_id"] != "nas" {
		t.Fatalf("not nas's rotate: %v", err)
	}
	if err := b.Check(shippedAnchor(t)); err != nil {
		code, _ := refusal.CodeOf(err)
		t.Fatalf("Go answers %q (%v), SPEC states accept", code, err)
	}
	// Relabelling this same proof isolates the body binding. The suite's
	// older negative carries an earlier nas rotation, which also refuses.
	b.Device = "printer"
	if err := b.Check(shippedAnchor(t)); err == nil {
		t.Fatal("wrong label accepted")
	} else if code, _ := refusal.CodeOf(err); code != refusal.Binding {
		t.Fatal(err)
	}
	b.Device = "nas"
	if err := b.Check(shippedAnchor(t)); err != nil {
		t.Fatal(err)
	}
	bad, err := Decode(read("proofs-bad/rotate-entry-other-device.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	if err := bad.Check(shippedAnchor(t)); err == nil {
		t.Fatal("existing wrong-label rotation accepted")
	} else if code, _ := refusal.CodeOf(err); code != refusal.Binding {
		t.Fatal(err)
	}
}
