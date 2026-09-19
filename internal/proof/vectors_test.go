package proof_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/trust"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
)

// The shipped served log and its bundles must verify from what a node holds --
// the trust anchor and the bundle -- and must agree with the replayed state.

func root() string { return filepath.Join("..", "..", "testdata", "vectors") }

func loadCases(t *testing.T) (string, []string, []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root(), "proofs", "cases.json"))
	if err != nil {
		t.Skip("served-log vectors not generated")
	}
	var meta struct {
		Origin  string   `json:"origin"`
		Devices []string `json:"devices"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}

	// The key comes from the shipped trust file, not from a seed repeated in
	// cases.json. A second copy is a second thing to keep in step, and the two
	// halves of the suite were signed by different keys for six checkpoints
	// before anything checked (2.9g).
	rawTrust, err := os.ReadFile(filepath.Join(root(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := trust.Parse(rawTrust)
	if err != nil {
		t.Fatal(err)
	}
	if anchor.Origin != meta.Origin {
		t.Fatalf("the bundles say origin %q, the trust file says %q", meta.Origin, anchor.Origin)
	}
	return meta.Origin, []string{anchor.LogKey}, meta.Devices
}

func TestEveryShippedBundleChecksOut(t *testing.T) {
	_, keys, devices := loadCases(t)
	if len(devices) == 0 {
		t.Fatal("no proof bundles were generated")
	}
	for _, id := range devices {
		raw, err := os.ReadFile(filepath.Join(root(), "proofs", id+".bundle"))
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := proof.Decode(raw)
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		if err := bundle.Check(keys); err != nil {
			t.Errorf("%s: shipped bundle does not check out: %v", id, err)
		}
		if bundle.Device != id {
			t.Errorf("%s: bundle names device %q", id, bundle.Device)
		}
	}
}

func TestEachBundleProvesTheEntryThatEnrolledItsDevice(t *testing.T) {
	_, keys, devices := loadCases(t)
	anchor, entries := loadFixture(t)
	st := replay.Replay(anchor, entries)

	for _, id := range devices {
		raw, _ := os.ReadFile(filepath.Join(root(), "proofs", id+".bundle"))
		bundle, err := proof.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := bundle.Check(keys); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		device, ok := st.Devices[id]
		if !ok || device.Status != state.StatusActive {
			t.Errorf("%s: a bundle exists for a device that is not active", id)
			continue
		}
		// The bundle must point at the entry that made this device active,
		// not merely at some entry in the log.
		if uint64(bundle.Index) != device.SinceIndex {
			t.Errorf("%s: bundle proves index %d, device became active at %d",
				id, bundle.Index, device.SinceIndex)
		}
		if string(bundle.Entry) != string(entries[bundle.Index]) {
			t.Errorf("%s: bundle carries a different entry than the log holds", id)
		}
	}
}

func TestBundlesAreRefusedUnderTheWrongLogKey(t *testing.T) {
	_, _, devices := loadCases(t)
	origin, _, _ := loadCases(t)
	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 3)).Public().(ed25519.PublicKey)
	wrong := []string{note.VerifierKey(origin, other)}

	for _, id := range devices {
		raw, _ := os.ReadFile(filepath.Join(root(), "proofs", id+".bundle"))
		bundle, err := proof.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := bundle.Check(wrong); err == nil {
			t.Errorf("%s: a bundle must not check out under a key that did not sign it", id)
		}
	}
}

func loadFixture(t *testing.T) (replay.Anchor, [][]byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root(), "log", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Anchor struct {
			Net         string `json:"net"`
			GenesisHash string `json:"genesis_hash"`
		} `json:"anchor"`
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	net, _ := hex.DecodeString(m.Anchor.Net)
	genesis, _ := hex.DecodeString(m.Anchor.GenesisHash)
	entries := make([][]byte, 0, len(m.Entries))
	for _, e := range m.Entries {
		b, err := os.ReadFile(filepath.Join(root(), "log", e.Name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, b)
	}
	return replay.Anchor{Net: net, GenesisHash: genesis}, entries
}
