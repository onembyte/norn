package proven

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/freshness"
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

// verified returns a real verification of the shipped log: the whole replay
// fixture, a
// signed checkpoint, six devices with a history behind them.
func verified(t *testing.T) (*logclient.Result, *trust.Trust) {
	t.Helper()
	doc := anchor(t)
	result, err := logclient.Verify(
		logclient.Dir(filepath.Join(vectorRoot(), "served")),
		logclient.Anchor{
			Anchor:  replay.Anchor{Net: doc.Net, GenesisHash: doc.GenesisHash},
			LogKeys: []string{doc.LogKey},
			Policy:  doc.Policy,
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
	result.QuorumTime = nil // a log no witness has cosigned
	set, err := FromResult(result, time.Now(), freshnessOf(t, result))
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
	set, err := FromResult(result, time.Unix(1_760_000_000, 0), freshnessOf(t, result))
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

	set, err := FromResult(result, time.Unix(1_760_000_000, 0), freshnessOf(t, result))
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
	set, err := FromResult(result, time.Unix(1_760_000_000, 0), freshnessOf(t, result))
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
	// Compared by value: `Checkpoint` holds a pointer, and `!=` on the struct
	// would compare addresses -- which agree only while both are nil, and so
	// would quietly stop testing anything the moment a witness time appeared.
	if !reflect.DeepEqual(back.Checkpoint, set.Checkpoint) ||
		len(back.Devices) != len(set.Devices) {
		t.Errorf("round trip differs:\n got %+v\nwant %+v", back, set)
	}
	if back.Freshness != set.Freshness {
		t.Errorf("freshness survived the round trip as %q, was %q",
			back.Freshness, set.Freshness)
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
	set, _ := FromResult(result, time.Unix(1_760_000_000, 0), freshnessOf(t, result))
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

// And when witnesses *have* cosigned, the file reports the instant they
// vouched for -- not the node's own clock, which appears only as
// `written_at_local_clock` and is labelled as local for that reason (A11).
func TestTheCheckpointCarriesWitnessTime(t *testing.T) {
	result, _ := verified(t)
	if result.QuorumTime == nil {
		t.Fatal("the fixture's log is cosigned; its verification must yield a witness time")
	}

	set, err := FromResult(result, time.Unix(1_900_000_000, 0), freshnessOf(t, result))
	if err != nil {
		t.Fatal(err)
	}
	if set.Checkpoint.CosignedAt == nil {
		t.Fatal("a cosigned checkpoint must publish the instant its witnesses vouched for")
	}
	if *set.Checkpoint.CosignedAt != result.QuorumTime.Unix() {
		t.Errorf("cosigned_at = %d, want the quorum time %d",
			*set.Checkpoint.CosignedAt, result.QuorumTime.Unix())
	}
	if set.WrittenAt == *set.Checkpoint.CosignedAt {
		t.Error("witness time and the local clock must not be the same field")
	}
}

// freshnessOf is the real freshness of a result, for the tests whose subject
// is something else: a node that adopted this checkpoint the instant its
// witnesses cosigned it.
func freshnessOf(t *testing.T, result *logclient.Result) Freshness {
	t.Helper()
	limits := freshness.LimitsFrom(result.State.Params, 0)
	var clock freshness.Clock
	if result.QuorumTime == nil {
		return View(&clock, limits, time.Time{}, 0)
	}
	clock.Observe(*result.QuorumTime, 0)
	return View(&clock, limits, *result.QuorumTime, 0)
}

// The state a consumer acts on: `freshness`, computed from witness time and a
// monotonic elapsed reading, never from this node's own clock (A11).
func TestFreshnessIsPublishedFromWitnessTime(t *testing.T) {
	result, _ := verified(t)
	if result.QuorumTime == nil {
		t.Fatal("the fixture's log is cosigned")
	}

	var clock freshness.Clock
	clock.Observe(*result.QuorumTime, 0)
	limits := freshness.LimitsFrom(result.State.Params, time.Hour)

	// The boundary is the *log's* `staleness`, not §4.5's default: this
	// fixture's log sets 900s with a `params` entry, and a node that used 600
	// anyway would disagree with the rest of its own network about when a view
	// has gone stale.
	if limits.Staleness != 900*time.Second {
		t.Fatalf("staleness = %v, want the log's own 900s", limits.Staleness)
	}

	for _, tc := range []struct {
		name string
		mono time.Duration
		want string
	}{
		{"just adopted", 0, freshness.Fresh},
		{"fourteen minutes on", 14 * time.Minute, freshness.Fresh},
		{"sixteen minutes on", 16 * time.Minute, freshness.Degraded},
		{"two hours on", 2 * time.Hour, freshness.HardStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := FromResult(result, time.Unix(1_900_000_000, 0),
				View(&clock, limits, *result.QuorumTime, tc.mono))
			if err != nil {
				t.Fatal(err)
			}
			if set.Freshness != tc.want {
				t.Errorf("freshness = %q, want %q", set.Freshness, tc.want)
			}
			if set.AgeSeconds == nil {
				t.Fatal("a node with a clock must publish the age it computed")
			}
			if *set.AgeSeconds != int64(tc.mono.Seconds()) {
				t.Errorf("age = %ds, want %ds", *set.AgeSeconds, int64(tc.mono.Seconds()))
			}
		})
	}
}

// And with no witness clock there is no age either -- the field is absent
// rather than zero, which would read as brand new.
func TestNoClockPublishesNoAge(t *testing.T) {
	result, _ := verified(t)
	result.QuorumTime = nil

	set, err := FromResult(result, time.Now(), View(&freshness.Clock{},
		freshness.Limits{Staleness: time.Minute}, time.Time{}, 0))
	if err != nil {
		t.Fatal(err)
	}
	if set.Freshness != Unknown {
		t.Errorf("freshness = %q, want %q", set.Freshness, Unknown)
	}
	if set.AgeSeconds != nil {
		t.Errorf("age = %v, want none", *set.AgeSeconds)
	}
}

// SPEC §5.3: "Entries whose `expires` is earlier than **the checkpoint time**
// are treated as `revoked` at evaluation time, not at replay, so state stays
// clock-independent."
//
// The checkpoint time is witness time (§10, GOSSIP part 5) -- not the node's
// wall clock, which A11 says decides nothing. A node with a fast clock would
// otherwise evict a device early and a slow one would keep an expired device,
// both silently, and both in contradiction of a normative line. It is also
// what T5 needs: a node whose clock is two hours out must leave its proven set
// **unchanged**, and that is only true if expiry never consults that clock.
func TestExpiryIsJudgedAgainstWitnessTimeNotTheLocalClock(t *testing.T) {
	result, _ := verified(t)
	if result.QuorumTime == nil {
		t.Fatal("the fixture's log is cosigned")
	}
	witness := *result.QuorumTime

	// A device the log gives an expiry, set just after witness time.
	expiring := ""
	for id, device := range result.State.Devices {
		if device.Expires > 0 {
			expiring = id
			break
		}
	}
	if expiring == "" {
		t.Skip("the fixture has no expiring device")
	}
	expiry := int64(result.State.Devices[expiring].Expires)

	// A node whose wall clock is a year past that expiry must still publish
	// the device, because the witnesses have not said so.
	skewed := time.Unix(expiry+365*24*3600, 0)
	set, err := FromResult(result, skewed, freshnessOf(t, result))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range set.Devices {
		if d.DeviceID == expiring {
			found = true
		}
	}
	if witness.Unix() < expiry && !found {
		t.Errorf("%s was dropped because *this machine's* clock says it expired; "+
			"witness time is %s and the expiry is %s (§5.3, A11)",
			expiring, witness, time.Unix(expiry, 0))
	}
	// And the local clock still appears where it is labelled as local.
	if set.WrittenAt != skewed.Unix() {
		t.Errorf("written_at_local_clock = %d, want this machine's clock", set.WrittenAt)
	}
}
