package proof

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/refusal"
)

func TestABundleAroundLaptopRevokeAcceptsUnderItsOwnLabel(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, tc := range []struct {
		name, kind, fixture string
		index               int64
	}{
		{"laptop-revoke", "revoke", "36-revoke-self-laptop", 36},
		{"laptop-since-revoked", "enroll", "2-enroll-laptop", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Decode(read(t, "proofs/"+tc.name+".bundle"))
			if err != nil {
				t.Fatal(err)
			}
			if b.Device != "laptop" || b.Index != tc.index || !bytes.Equal(b.Entry, read(t, "log/"+tc.fixture+".cbor")) || b.Checkpoint != string(read(t, "served/checkpoint")) {
				t.Fatal("bundle must prove the fixture's real laptop entry under the served head")
			}
			env, err := entry.Decode(b.Entry)
			if err != nil {
				t.Fatal(err)
			}
			id := env.Body["device_id"]
			if env.T == "enroll" {
				request, err := enrollreq.Decode(env.Body["request"].([]byte))
				if err != nil {
					t.Fatal(err)
				}
				id = request.DeviceID
			}
			if env.T != tc.kind || id != "laptop" {
				t.Fatalf("entry must be laptop's %s", tc.kind)
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
			if err := json.Unmarshal(read(t, "proofs/cases.json"), &m); err != nil {
				t.Fatal(err)
			}
			var says string
			found := false
			for _, c := range m.Sound {
				if c.Name == tc.name {
					found = c.File == tc.name+".bundle" && c.Device == b.Device && c.Index == b.Index
					says = c.Says
				}
			}
			if len(m.Sound) != 5 || !found || m.Codes[tc.name] != "accept" {
				t.Fatal("proofs manifest must list both laptop cases beside the sound nas rotation")
			}
			if _, ok := m.Installs[b.Device]; ok || !strings.Contains(says, "installs omits laptop") || !strings.Contains(m.Comment, "installs omits laptop") {
				t.Fatal("the manifest must state that the sound laptop bundle installs no laptop key")
			}
			// The entry, proof and checkpoint stay honest. Changing only the label
			// isolates the binding through the device id named by the entry.
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
		})
	}
}
