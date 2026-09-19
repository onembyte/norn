package proven

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/trust"
)

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func anchor(t *testing.T) *trust.Trust {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// verified returns a real verification of the shipped log: 90 entries, a
// signed checkpoint, six devices with a history behind them.
func verified(t *testing.T) (*logclient.Result, *trust.Trust) {
	t.Helper()
	doc := anchor(t)
	result, err := logclient.Verify(
		logclient.Dir(filepath.Join(vectorRoot(), "served")),
		logclient.Anchor{
			Anchor:  replay.Anchor{Net: doc.Net, GenesisHash: doc.GenesisHash},
			LogKeys: []string{doc.LogKey},
		})
	if err != nil {
		t.Fatal(err)
	}
	return result, doc
}

// The file must not assert a freshness nobody can establish. With no witness
// cosignatures there is no clock (A11, GOSSIP.md part 5), so the state is
// `unknown` and a consumer has to handle it -- rather than `"degraded": false`,
// which would read as "all is well".
func TestFreshnessIsUnknownWithoutWitnesses(t *testing.T) {
	result, _ := verified(t)
	set, err := FromResult(result, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if set.Freshness != Unknown {
		t.Errorf("freshness = %q, want %q", set.Freshness, Unknown)
	}
	if set.Checkpoint.CosignedAt != nil {
		t.Error("a cosignature time appeared from nowhere")
	}

	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"degraded"`) {
		t.Error("a boolean `degraded` cannot express what this node knows")
	}
	if !strings.Contains(string(body), "written_at_local_clock") {
		t.Error("the local clock must be labelled as local")
	}
}

// Proven is active *and* unexpired. The difference is one line, and two copies
// of it is how a contractor's laptop stays in somebody's peer table.
func TestProvenExcludesTheExpired(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := []struct {
		why    string
		device state.Device
		want   bool
	}{
		{"active, no expiry", state.Device{Status: state.StatusActive}, true},
		{"active, expires later", state.Device{Status: state.StatusActive,
			Expires: uint64(now.Unix()) + 60}, true},
		{"active, expired", state.Device{Status: state.StatusActive,
			Expires: uint64(now.Unix()) - 1}, false},
		{"active, expiring this second", state.Device{Status: state.StatusActive,
			Expires: uint64(now.Unix())}, false},
		{"revoked", state.Device{Status: state.StatusRevoked}, false},
	}
	for _, c := range cases {
		if got := IsProven(c.device, now); got != c.want {
			t.Errorf("%s: proven = %v, want %v", c.why, got, c.want)
		}
	}
}

func TestFromResultCarriesTheFixturesDevices(t *testing.T) {
	result, _ := verified(t)
	set, err := FromResult(result, time.Unix(1_760_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if set.Version != Version {
		t.Errorf("version = %d", set.Version)
	}
	if set.Checkpoint.Size != result.Checkpoint.Size || set.Checkpoint.Origin == "" {
		t.Errorf("checkpoint = %+v", set.Checkpoint)
	}
	if len(set.Devices) == 0 {
		t.Fatal("no devices")
	}
	for _, device := range set.Devices {
		if device.DeviceID == "" || device.WgPk == "" {
			t.Errorf("empty device: %+v", device)
		}
		// WireGuard's own encoding, so an operator can paste it into `wg`.
		if len(device.WgPk) != 44 || !strings.HasSuffix(device.WgPk, "=") {
			t.Errorf("%s: key is not base64: %q", device.DeviceID, device.WgPk)
		}
		if _, err := device.Key(); err != nil {
			t.Errorf("%s: %v", device.DeviceID, err)
		}
		if !strings.HasPrefix(device.Proof, ProofDir+"/") {
			t.Errorf("%s: proof = %q", device.DeviceID, device.Proof)
		}
	}
	// The fixture revokes some devices and expires a contractor; the proven
	// set must be smaller than the device list.
	if len(set.Devices) >= len(result.State.Devices) {
		t.Errorf("%d proven of %d devices: revoked and expired ones leaked through",
			len(set.Devices), len(result.State.Devices))
	}
}

// A `proof` field naming a bundle that is not there would be worse than no
// field: an alarm would point at evidence that does not exist.
func TestEveryDeviceGetsACheckableBundle(t *testing.T) {
	result, doc := verified(t)
	dir := t.TempDir()

	set, err := FromResult(result, time.Unix(1_760_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, set, result); err != nil {
		t.Fatal(err)
	}

	for _, device := range set.Devices {
		raw, err := os.ReadFile(filepath.Join(dir, device.Proof))
		if err != nil {
			t.Fatalf("%s: %v", device.DeviceID, err)
		}
		bundle, err := proof.Decode(raw)
		if err != nil {
			t.Fatalf("%s: %v", device.DeviceID, err)
		}
		// Checkable by someone holding only norn.trust -- which is the whole
		// point of a bundle (§8).
		if err := bundle.Check([]string{doc.LogKey}); err != nil {
			t.Errorf("%s: the bundle does not check out: %v", device.DeviceID, err)
		}
		if bundle.Device != device.DeviceID {
			t.Errorf("bundle names %q, file names %q", bundle.Device, device.DeviceID)
		}
	}
}

func TestWriteThenRead(t *testing.T) {
	result, _ := verified(t)
	dir := t.TempDir()
	set, err := FromResult(result, time.Unix(1_760_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, set, result); err != nil {
		t.Fatal(err)
	}

	back, err := Read(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if back.Checkpoint != set.Checkpoint || len(back.Devices) != len(set.Devices) {
		t.Errorf("round trip differs:\n got %+v\nwant %+v", back, set)
	}
	if back.Freshness != Unknown {
		t.Errorf("freshness = %q", back.Freshness)
	}

	// Readable by other tools, so world-readable and no leftovers.
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".norn-") {
			t.Errorf("a temporary file was left behind: %s", entry.Name())
		}
	}
}

// Somebody reads this file while nornd rewrites it, every T_poll, forever.
func TestRewritingIsAtomic(t *testing.T) {
	result, _ := verified(t)
	dir := t.TempDir()
	set, _ := FromResult(result, time.Unix(1_760_000_000, 0))
	if err := Write(dir, set, result); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, FileName)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			if err := Write(dir, set, nil); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 200; i++ {
		if _, err := Read(path); err != nil {
			t.Fatalf("a reader saw a file that was not whole: %v", err)
		}
	}
	<-done
}

func TestReadRejectsAnotherVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte(`{"version":99,"devices":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("read a file from a schema this build does not know")
	}
}
