package proven

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/state"
)

func TestASoundRevokeBundleInstallsNothingWhileNasInstallsItsReplayedKey(t *testing.T) {
	result, doc := verified(t)
	read := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(vectorRoot(), path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var manifest struct {
		Installs map[string]string
		Sound    []struct {
			Name, File, Device string
			Index              int64
		}
	}
	if err := json.Unmarshal(read(t, "proofs/cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if result.Checkpoint.Size != 162 || result.State.Devices["laptop"].Status != state.StatusRevoked {
		t.Fatal("the served checkpoint must leave laptop revoked at size 162")
	}
	for _, rejection := range result.State.Rejected {
		if rejection.Index == 36 || rejection.Index == 2 {
			t.Fatal("replay must accept laptop's enrollment at index 2 and self-revoke at index 36")
		}
	}
	for _, tc := range []struct {
		file, device string
		index        int64
		installed    bool
	}{
		{"laptop-revoke.bundle", "laptop", 36, false},
		{"laptop-since-revoked.bundle", "laptop", 2, false},
		{"nas.bundle", "nas", 1, true},
	} {
		t.Run(tc.file, func(t *testing.T) {
			if tc.device == "laptop" {
				found := false
				for _, c := range manifest.Sound {
					if c.File == tc.file && c.Name+".bundle" == tc.file && c.Device == tc.device && c.Index == tc.index {
						found = true
					}
				}
				if !found {
					t.Fatal("sound must explicitly list " + tc.file)
				}
			}
			b, err := proof.Decode(read(t, "proofs/"+tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if b.Device != tc.device || b.Index != tc.index || b.Checkpoint != result.SignedCheckpoint || !bytes.Equal(b.Entry, result.Served[tc.index]) {
				t.Fatal("bundle must belong to the checkpoint Go verified and replayed")
			}
			if err := b.Check(proof.Anchor{Origin: doc.Origin, LogKeys: []string{doc.LogKey}, Policy: doc.Policy}); err != nil {
				t.Fatalf("bundle checks must accept before condition 3: %v", err)
			}
			// Exercise the node's key selection, rather than restating its
			// active check over state.json. A bundle alone installs nobody.
			set, err := FromResult(result, time.Unix(1_760_000_000, 0), freshnessOf(t, result))
			if err != nil {
				t.Fatal(err)
			}
			want, listed := manifest.Installs[b.Device]
			if listed != tc.installed || (tc.installed && want == "") {
				t.Fatal("installs must name nas's replayed key and omit laptop")
			}
			found := false
			for _, device := range set.Devices {
				if device.DeviceID != b.Device {
					continue
				}
				found = true
				if !tc.installed {
					t.Fatalf("Go installs a key for revoked %s; SPEC condition 3 installs nothing", b.Device)
				}
				key, err := device.Key()
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(key[:]) != want || want != result.State.Devices[b.Device].WgPk {
					t.Fatalf("Go installs %s; SPEC condition 3 and installs require %s", hex.EncodeToString(key[:]), want)
				}
			}
			if found != tc.installed {
				t.Fatalf("Go installs %s: %t; SPEC condition 3 requires %t", b.Device, found, tc.installed)
			}
		})
	}
}
