// Package agent is one cycle of what `nornd` does: verify the log, work out
// which peers it proves, and reconcile the interface with that.
//
// The cycle is a method rather than a loop so that the behaviour worth testing
// — what happens when the log is unreachable, when it stops verifying, when
// somebody else is writing to the table — is a function call and not a race
// against a timer.
//
// The rule that shapes everything here is `ENFORCEMENT.md` part 8: **a failure
// must never widen the peer table, and must never empty it.** A log that goes
// down is an outage of Norn's ability to learn new facts; it is not a reason to
// disconnect a network, and it is not a reason to stop evicting intruders.
package agent

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/onembyte/norn/internal/endpoint"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

// Event kinds this package raises on top of the reconciler's.
const (
	// VerifyFailed: the log could not be verified this cycle.
	VerifyFailed = "VERIFY_FAILED"
	// EnforcingOnStaleState: the log is unreachable and the interface is being
	// held to the last set that did verify. Worth saying out loud, because the
	// facts being enforced are older than they look.
	EnforcingOnStaleState = "ENFORCING_ON_STALE_STATE"
	// InterfaceUnavailable: the WireGuard interface could not be read.
	InterfaceUnavailable = "INTERFACE_UNAVAILABLE"
	// NoStateYet: nothing has verified since start, so there is nothing to
	// enforce. The table is left exactly as it is.
	NoStateYet = "NO_STATE_YET"
	// ProviderClaim: a provider had opinions about devices the log does not
	// prove, or none about devices it does.
	ProviderClaim = "PROVIDER_CLAIM"
)

// Event is something an operator should know about.
type Event struct {
	Kind    string
	Message string
	// Peer is set when the event is about one key.
	Peer *reconcile.Alarm
}

// Config is what an agent needs. Everything it talks to is an interface, so a
// test substitutes a directory for a log and a fake for a kernel.
type Config struct {
	Anchor   *trust.Trust
	Fetcher  logclient.Fetcher
	Device   peertable.Device
	Provider endpoint.Provider
	Mode     reconcile.Mode
	// RunDir receives proven.json and its bundles; empty means do not publish.
	RunDir string
	Now    func() time.Time
	Emit   func(Event)
}

// Agent runs the cycle and remembers the last state that verified.
type Agent struct {
	cfg  Config
	last *logclient.Result
}

// New checks what must be true before a node starts at all.
//
// `ENFORCEMENT.md` part 8: a missing or invalid trust file means refuse to
// start, in every mode. A node that started without an anchor would be a node
// enforcing nothing while looking like it was working.
func New(cfg Config) (*Agent, error) {
	if cfg.Anchor == nil {
		return nil, errors.New("agent: no trust file; a node without an anchor proves nothing")
	}
	if err := cfg.Anchor.Validate(); err != nil {
		return nil, fmt.Errorf("agent: the trust file is not a usable anchor: %w", err)
	}
	if cfg.Fetcher == nil || cfg.Device == nil {
		return nil, errors.New("agent: a log and an interface are both required")
	}
	if cfg.Mode == "" {
		cfg.Mode = reconcile.Observe // D-005: observe unless told otherwise
	}
	if cfg.Provider == nil {
		cfg.Provider = endpoint.None{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Emit == nil {
		cfg.Emit = func(Event) {}
	}
	return &Agent{cfg: cfg}, nil
}

// Mode reports the mode this agent runs in.
func (a *Agent) Mode() reconcile.Mode { return a.cfg.Mode }

// Once verifies the log and reconciles the interface with it.
//
// It returns an error when the cycle could not do its job, having already done
// whatever was safe: an error here means "this cycle learned nothing", never
// "the peer table has been abandoned".
func (a *Agent) Once() error {
	result, verifyErr := logclient.Verify(a.cfg.Fetcher, logclient.Anchor{
		Anchor:  replay.Anchor{Net: a.cfg.Anchor.Net, GenesisHash: a.cfg.Anchor.GenesisHash},
		LogKeys: []string{a.cfg.Anchor.LogKey},
	})
	if verifyErr != nil {
		a.emit(Event{Kind: VerifyFailed, Message: verifyErr.Error()})
		if a.last == nil {
			// Nothing has ever verified. Enforcing an empty proven set would
			// mean disconnecting every peer because a log was unreachable at
			// boot -- an outage Norn caused, protecting nothing.
			a.emit(Event{Kind: NoStateYet,
				Message: "no state has verified yet; the interface is left untouched"})
			return verifyErr
		}
		a.emit(Event{Kind: EnforcingOnStaleState,
			Message: "holding the interface to the last state that verified"})
		result = a.last
	} else {
		a.last = result
	}

	if err := a.reconcile(result); err != nil {
		return err
	}
	if verifyErr == nil && a.cfg.RunDir != "" {
		set, err := proven.FromResult(result, a.cfg.Now())
		if err != nil {
			return err
		}
		if err := proven.Write(a.cfg.RunDir, set, result); err != nil {
			return err
		}
	}
	return verifyErr
}

// reconcile turns a verified state into peer-table actions.
func (a *Agent) reconcile(result *logclient.Result) error {
	desired, report := a.desired(result)
	for _, id := range report.Unproven {
		a.emit(Event{Kind: ProviderClaim,
			Message: fmt.Sprintf("the endpoint provider has hints for %q, which the log does not prove", id)})
	}
	for _, id := range report.Unrouted {
		a.emit(Event{Kind: ProviderClaim,
			Message: fmt.Sprintf("%q is proven but no provider gave it any routes", id)})
	}

	actual, err := a.cfg.Device.Peers()
	if err != nil {
		a.emit(Event{Kind: InterfaceUnavailable, Message: err.Error()})
		return fmt.Errorf("agent: reading the interface: %w", err)
	}

	plan := reconcile.Decide(a.cfg.Mode, actual, desired)
	if plan.Invalid {
		return fmt.Errorf("agent: %q is not a mode", a.cfg.Mode)
	}
	for i := range plan.Alarms {
		alarm := plan.Alarms[i]
		a.emit(Event{Kind: alarm.Kind, Peer: &alarm,
			Message: fmt.Sprintf("%s %s", alarm.Kind, alarm.Key.Short())})
	}
	return reconcile.Apply(a.cfg.Device, plan)
}

// desired is the proven set dressed with whatever the provider knows.
func (a *Agent) desired(result *logclient.Result) ([]peertable.Peer, endpoint.Report) {
	now := a.cfg.Now()
	var devices []endpoint.Device
	for _, id := range proven.Devices(result.State, now) {
		device := result.State.Devices[id]
		key, err := keyOf(device.WgPk)
		if err != nil {
			a.emit(Event{Kind: ProviderClaim,
				Message: fmt.Sprintf("%q has an unreadable key in the log: %v", id, err)})
			continue
		}
		devices = append(devices, endpoint.Device{ID: id, Key: key, Labels: device.Labels})
	}
	return endpoint.Desired(devices, a.cfg.Provider)
}

func (a *Agent) emit(event Event) { a.cfg.Emit(event) }

// keyOf converts the hex key §5.3 stores into the one the peer table uses.
func keyOf(hexKey string) (peertable.Key, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return peertable.Key{}, err
	}
	return peertable.KeyFromBytes(raw)
}
