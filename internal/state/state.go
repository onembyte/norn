// Package state holds the replayed network state of SPEC.md §5.3 and its
// canonical serialisation.
//
// State owns its shape and its bytes, and nothing else: whether an entry is
// allowed to take effect is replay's decision, not this package's. Byte strings
// are kept as lowercase hex here because that is how §14 renders them and how
// they are keyed in active_wg; converting back and forth would only invite the
// two representations to disagree.
package state

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/onembyte/norn/internal/cjson"
)

// Device status values (§5.3).
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// DefaultParams are the §4.5 defaults every state starts from.
func DefaultParams() map[string]any {
	return map[string]any{
		"checkpoint_interval": uint64(60),
		"staleness":           uint64(600),
		"mmd":                 uint64(60),
		"rotate_needs_signer": false,
	}
}

// Device is one record in `devices` (§5.3).
type Device struct {
	DevicePk   string            `json:"device_pk"`
	WgPk       string            `json:"wg_pk"`
	Status     string            `json:"status"`
	SinceIndex uint64            `json:"since_index"`
	Labels     map[string]string `json:"labels"`
	Expires    uint64            `json:"expires"`
}

// LogKey is one recorded log-key rotation. SinceIndex is the index of the
// `log_key` entry itself -- not a log size, and not the index from which the
// key becomes valid (§5.3).
type LogKey struct {
	Overlap    uint64 `json:"overlap"`
	Pk         string `json:"pk"`
	SinceIndex uint64 `json:"since_index"`
}

// Rejection records one entry that did not take effect.
type Rejection struct {
	Index  uint64 `json:"index"`
	Reason string `json:"reason"`
}

// State is the result of replaying a log. Every field is always present in the
// canonical form, including after an abort at genesis.
type State struct {
	Name      string
	Net       []byte
	Size      uint64
	RootThr   uint64
	SignerThr uint64
	Roots     map[string]string // kid -> hex public key
	Signers   map[string]string
	Params    map[string]any
	Policy    string
	LogKeys   []LogKey
	Devices   map[string]Device
	ActiveWg  map[string]string // hex wg key -> device id
	Rejected  []Rejection
}

// New returns the zero state for a network, before any entry is applied.
func New(net []byte) *State {
	return &State{
		Net:      net,
		Roots:    map[string]string{},
		Signers:  map[string]string{},
		Params:   DefaultParams(),
		LogKeys:  []LogKey{},
		Devices:  map[string]Device{},
		ActiveWg: map[string]string{},
		Rejected: []Rejection{},
	}
}

// Clone is a deep copy: a fold resumed from a held state must not move the
// held state when it fails halfway.
func (s *State) Clone() *State {
	out := &State{
		Name: s.Name, Net: append([]byte(nil), s.Net...), Size: s.Size,
		RootThr: s.RootThr, SignerThr: s.SignerThr, Policy: s.Policy,
		Roots: copyStrings(s.Roots), Signers: copyStrings(s.Signers),
		Params:   make(map[string]any, len(s.Params)),
		LogKeys:  append([]LogKey{}, s.LogKeys...),
		Devices:  make(map[string]Device, len(s.Devices)),
		ActiveWg: copyStrings(s.ActiveWg),
		Rejected: append([]Rejection{}, s.Rejected...),
	}
	for k, v := range s.Params {
		out.Params[k] = v // scalars only (§4.5)
	}
	for id, d := range s.Devices {
		d.Labels = copyStrings(d.Labels)
		out.Devices[id] = d
	}
	return out
}

func copyStrings(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ErrState reports a malformed state document.
var ErrState = errors.New("malformed state")

// MarshalCanonical renders the state per §14, terminated by the single newline
// §14.1 requires.
func (s *State) MarshalCanonical() ([]byte, error) {
	devices := make(map[string]any, len(s.Devices))
	for id, d := range s.Devices {
		labels := make(map[string]any, len(d.Labels))
		for k, v := range d.Labels {
			labels[k] = v
		}
		devices[id] = map[string]any{
			"device_pk": d.DevicePk, "wg_pk": d.WgPk, "status": d.Status,
			"since_index": d.SinceIndex, "labels": labels, "expires": d.Expires,
		}
	}
	logKeys := make([]any, 0, len(s.LogKeys))
	for _, k := range s.LogKeys {
		logKeys = append(logKeys, map[string]any{
			"overlap": k.Overlap, "pk": k.Pk, "since_index": k.SinceIndex})
	}
	rejected := make([]any, 0, len(s.Rejected))
	for _, r := range s.Rejected {
		rejected = append(rejected, map[string]any{"index": r.Index, "reason": r.Reason})
	}
	doc := map[string]any{
		"name": s.Name, "net": s.Net, "size": s.Size,
		"root_thr": s.RootThr, "signer_thr": s.SignerThr,
		"roots": stringMap(s.Roots), "signers": stringMap(s.Signers),
		"params": s.Params, "policy": s.Policy,
		"log_keys": logKeys, "devices": devices,
		"active_wg": stringMap(s.ActiveWg), "rejected": rejected,
	}
	out, err := cjson.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func stringMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Parse reads a canonical state document back into the typed model, so that a
// round trip can be checked byte for byte.
func Parse(raw []byte) (*State, error) {
	var doc struct {
		Name      string            `json:"name"`
		Net       string            `json:"net"`
		Size      uint64            `json:"size"`
		RootThr   uint64            `json:"root_thr"`
		SignerThr uint64            `json:"signer_thr"`
		Roots     map[string]string `json:"roots"`
		Signers   map[string]string `json:"signers"`
		Params    map[string]any    `json:"params"`
		Policy    string            `json:"policy"`
		LogKeys   []LogKey          `json:"log_keys"`
		Devices   map[string]Device `json:"devices"`
		ActiveWg  map[string]string `json:"active_wg"`
		Rejected  []Rejection       `json:"rejected"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	}
	net, err := hex.DecodeString(doc.Net)
	if err != nil {
		return nil, fmt.Errorf("%w: net is not hex", ErrState)
	}
	params := map[string]any{}
	for k, v := range doc.Params {
		switch value := v.(type) {
		case bool:
			params[k] = value
		case float64:
			params[k] = uint64(value)
		default:
			return nil, fmt.Errorf("%w: param %q has type %T", ErrState, k, v)
		}
	}
	s := &State{
		Name: doc.Name, Net: net, Size: doc.Size,
		RootThr: doc.RootThr, SignerThr: doc.SignerThr,
		Roots: orEmptyStrings(doc.Roots), Signers: orEmptyStrings(doc.Signers),
		Params: params, Policy: doc.Policy,
		LogKeys: orEmptyLogKeys(doc.LogKeys), Devices: orEmptyDevices(doc.Devices),
		ActiveWg: orEmptyStrings(doc.ActiveWg), Rejected: orEmptyRejections(doc.Rejected),
	}
	for id, d := range s.Devices {
		if d.Labels == nil {
			d.Labels = map[string]string{}
			s.Devices[id] = d
		}
	}
	return s, nil
}

func orEmptyStrings(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func orEmptyDevices(m map[string]Device) map[string]Device {
	if m == nil {
		return map[string]Device{}
	}
	return m
}

func orEmptyLogKeys(s []LogKey) []LogKey {
	if s == nil {
		return []LogKey{}
	}
	return s
}

func orEmptyRejections(s []Rejection) []Rejection {
	if s == nil {
		return []Rejection{}
	}
	return s
}
