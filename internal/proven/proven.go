// Package proven is the interface between the verifier and the enforcer
// (`ENFORCEMENT.md` part 9).
//
// In `nornd` the two live in one process, so this file is not how they talk —
// it is how everything *else* finds out: the monitor, Home Assistant, a
// support bundle, an operator with `jq`. That makes it an output the project
// has to be as careful with as a protocol message, because a number here that
// nobody can justify is a number somebody will act on.
//
// Which is why freshness is a state and not a boolean. `GOSSIP.md` part 5 puts
// the clock in witness time; with no cosignatures there is no clock, and a
// `"degraded": false` would assert something no node can know. The field says
// `"unknown"` instead, and a consumer must handle it.
package proven

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlog"
)

// Version is the schema version of proven.json.
const Version = 1

// Freshness states, from `GOSSIP.md` part 5's machine, plus the one that
// machine cannot express yet.
const (
	Fresh     = "fresh"
	Degraded  = "degraded"
	HardStale = "hard_stale"
	// Unknown means no witness has cosigned this checkpoint, so its age has no
	// answer -- not "it is fine", and not "it is stale".
	Unknown = "unknown"
)

// FileName is where the proven set is published.
const FileName = "proven.json"

// ProofDir holds one self-contained bundle per proven device.
const ProofDir = "proofs"

// Checkpoint is the head this view came from.
type Checkpoint struct {
	Origin string `json:"origin"`
	Size   int64  `json:"size"`
	Root   string `json:"root"`
	// CosignedAt is witness time, in unix seconds. Absent until a witness
	// cosigns: a node's own clock is not evidence (A11).
	CosignedAt *int64 `json:"cosigned_at"`
}

// Device is one peer the log proves.
type Device struct {
	DeviceID string            `json:"device_id"`
	WgPk     string            `json:"wg_pk"` // base64, as WireGuard writes keys
	Labels   map[string]string `json:"labels"`
	Expires  int64             `json:"expires"`
	// Proof names the bundle beside this file that proves the claim, so an
	// alarm can point at evidence instead of asserting.
	Proof string `json:"proof"`
	// SinceIndex is the log entry that made this device active.
	SinceIndex int64 `json:"since_index"`
}

// Set is the published view.
type Set struct {
	Version    int        `json:"version"`
	Checkpoint Checkpoint `json:"checkpoint"`
	Freshness  string     `json:"freshness"`
	Devices    []Device   `json:"devices"`
	// WrittenAt is this node's own clock, and is labelled as such: it is for
	// noticing a stopped daemon, never for deciding whether a view is fresh.
	WrittenAt int64 `json:"written_at_local_clock"`
}

// Key returns a device's WireGuard key in the form the peer table uses.
func (d Device) Key() (peertable.Key, error) {
	raw, err := base64.StdEncoding.DecodeString(d.WgPk)
	if err != nil {
		return peertable.Key{}, fmt.Errorf("proven: %s: %w", d.DeviceID, err)
	}
	return peertable.KeyFromBytes(raw)
}

// IsProven reports whether the log currently vouches for this device: active,
// and not past an expiry it set for itself.
//
// One definition, in one place. "Active" and "proven" differ by exactly this
// expiry check, and two copies of that difference is how a revoked contractor's
// laptop stays in somebody's peer table.
func IsProven(device state.Device, now time.Time) bool {
	if device.Status != state.StatusActive {
		return false
	}
	return device.Expires == 0 || int64(device.Expires) > now.Unix()
}

// Devices returns the proven devices of a state, in a stable order.
func Devices(st *state.State, now time.Time) []string {
	var out []string
	for id, device := range st.Devices {
		if IsProven(device, now) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// FromResult builds the view a verified log implies.
func FromResult(result *logclient.Result, now time.Time) (Set, error) {
	set := Set{
		Version: Version,
		Checkpoint: Checkpoint{
			Origin: result.Checkpoint.Origin,
			Size:   result.Checkpoint.Size,
			Root:   hex.EncodeToString(result.Checkpoint.Root[:]),
		},
		// No cosignature has been seen, so there is no witness time and no
		// state to compute from it. Phase 4 replaces this, and until then
		// saying "fresh" would be a guess wearing a field name.
		Freshness: Unknown,
		WrittenAt: now.Unix(),
	}

	for _, id := range Devices(result.State, now) {
		device := result.State.Devices[id]
		raw, err := hex.DecodeString(device.WgPk)
		if err != nil {
			return Set{}, fmt.Errorf("proven: %s has an unreadable key: %w", id, err)
		}
		set.Devices = append(set.Devices, Device{
			DeviceID: id, WgPk: base64.StdEncoding.EncodeToString(raw),
			Labels: device.Labels, Expires: int64(device.Expires),
			Proof: filepath.Join(ProofDir, id+".bundle"), SinceIndex: int64(device.SinceIndex),
		})
	}
	return set, nil
}

// Write publishes the set and a proof bundle per device, atomically.
//
// Atomically matters because somebody else is reading this while `nornd`
// writes it — every T_poll, forever. A reader that caught a half-written file
// would see a peer set that never existed.
func Write(dir string, set Set, result *logclient.Result) error {
	if err := os.MkdirAll(filepath.Join(dir, ProofDir), 0o755); err != nil {
		return fmt.Errorf("proven: %w", err)
	}
	if result != nil {
		if err := writeBundles(dir, set, result); err != nil {
			return err
		}
	}
	body, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return fmt.Errorf("proven: %w", err)
	}
	return replace(filepath.Join(dir, FileName), append(body, '\n'))
}

// writeBundles writes the evidence the file points at. A `proof` field naming
// a bundle that is not there would be worse than no field.
func writeBundles(dir string, set Set, result *logclient.Result) error {
	tree, err := tlog.Build(result.Served)
	if err != nil {
		return fmt.Errorf("proven: rebuilding the tree: %w", err)
	}
	for _, device := range set.Devices {
		index := device.SinceIndex
		if index < 0 || index >= int64(len(result.Served)) {
			return fmt.Errorf("proven: %s claims entry %d of %d",
				device.DeviceID, index, len(result.Served))
		}
		inclusion, err := tree.InclusionProof(index)
		if err != nil {
			return fmt.Errorf("proven: %s: %w", device.DeviceID, err)
		}
		bundle, err := proof.Build(device.DeviceID, index, result.Served[index],
			inclusion, result.SignedCheckpoint)
		if err != nil {
			return fmt.Errorf("proven: %s: %w", device.DeviceID, err)
		}
		encoded, err := bundle.Encode()
		if err != nil {
			return fmt.Errorf("proven: %s: %w", device.DeviceID, err)
		}
		if err := replace(filepath.Join(dir, device.Proof), encoded); err != nil {
			return err
		}
	}
	return nil
}

// Read loads a published set, for the monitor and for tests.
func Read(path string) (Set, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Set{}, fmt.Errorf("proven: %w", err)
	}
	var set Set
	if err := json.Unmarshal(raw, &set); err != nil {
		return Set{}, fmt.Errorf("proven: %s: %w", path, err)
	}
	if set.Version != Version {
		return Set{}, fmt.Errorf("proven: %s is version %d, this build reads %d",
			path, set.Version, Version)
	}
	return set, nil
}

func replace(path string, body []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".norn-*")
	if err != nil {
		return fmt.Errorf("proven: %w", err)
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(body); err != nil {
		temp.Close()
		return fmt.Errorf("proven: %w", err)
	}
	if err := temp.Chmod(0o644); err != nil {
		temp.Close()
		return fmt.Errorf("proven: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("proven: %w", err)
	}
	return os.Rename(temp.Name(), path)
}
