package proof

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/refusal"
)

func TestABundleAroundLaptopRevokeAcceptsUnderItsOwnLabel(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	b, err := Decode(read("proofs/laptop-revoke.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Device != "laptop" || b.Index != 36 || !bytes.Equal(b.Entry, read("log/36-revoke-self-laptop.cbor")) || b.Checkpoint != string(read("served/checkpoint")) {
		t.Fatal("bundle must prove the fixture's real laptop self-revoke under the served head")
	}
	env, err := entry.Decode(b.Entry)
	if err != nil || env.T != "revoke" || env.Body["device_id"] != "laptop" {
		t.Fatalf("not laptop's revoke: %v", err)
	}
	if err := b.Check(shippedAnchor(t)); err != nil {
		code, _ := refusal.CodeOf(err)
		t.Fatalf("Go answers %q (%v), SPEC states accept", code, err)
	}
	var m struct {
		Sound []struct {
			Name, File, Device, Says string
			Index                    int64
		}
		Codes    map[string]string
		Installs map[string]string
		Comment  string
	}
	if err := json.Unmarshal(read("proofs/cases.json"), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Sound) != 2 || m.Sound[1].Name != "laptop-revoke" || m.Sound[1].File != "laptop-revoke.bundle" || m.Sound[1].Device != b.Device || m.Sound[1].Index != b.Index || m.Codes["laptop-revoke"] != "accept" {
		t.Fatal("proofs manifest must list the laptop revoke beside the sound nas rotation")
	}
	if _, ok := m.Installs[b.Device]; ok || !strings.Contains(m.Sound[1].Says, "installs omits laptop") || !strings.Contains(m.Comment, "installs omits laptop") {
		t.Fatal("the manifest must state that the sound revoke installs no laptop key")
	}
	// The entry, proof and checkpoint stay honest. Changing only the label
	// isolates the binding through the revoke body's device_id.
	b.Device = "nas"
	if err := b.Check(shippedAnchor(t)); err == nil {
		t.Fatal("wrong label accepted")
	} else if code, _ := refusal.CodeOf(err); code != refusal.Binding {
		t.Fatal(err)
	}
	b.Device = "laptop"
	if err := b.Check(shippedAnchor(t)); err != nil {
		t.Fatal(err)
	}
}
