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
	"github.com/onembyte/norn/internal/fight"
	"github.com/onembyte/norn/internal/freshness"
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
	// ClockSkew: this machine's wall clock disagrees with witness time by more
	// than Δclock. It is the only finding the wall clock is allowed to
	// produce, and it changes nothing -- not the freshness state, not the
	// proven set, not the peer table (A11, GOSSIP part 5 and T5).
	ClockSkew = "CLOCK_SKEW"
	// Degraded: the view is older than `staleness` and nothing newer has been
	// cosigned. The proven set is kept -- a quiet log is not evidence that a
	// peer stopped being proven -- but it is said out loud, on a cadence, for
	// as long as it lasts (GOSSIP part 5).
	Degraded = "DEGRADED"
	// HardStale: the view aged past S_hard, so the enforcer drops every peer.
	// This is a deliberate outage: past that age this node would rather be
	// disconnected than enforce a view nobody has vouched for since.
	HardStale = "HARD_STALE"
)

// DefaultDegradedAlarmEvery is GOSSIP part 5's "alarm every 5 min".
const DefaultDegradedAlarmEvery = 5 * time.Minute

const (
	// InterfaceUnavailable: the WireGuard interface could not be read.
	InterfaceUnavailable = "INTERFACE_UNAVAILABLE"
	// NoStateYet: nothing has verified since start, so there is nothing to
	// enforce. The table is left exactly as it is.
	NoStateYet = "NO_STATE_YET"
	// ProviderClaim: a provider had opinions about devices the log does not
	// prove, or none about devices it does.
	ProviderClaim = "PROVIDER_CLAIM"
	// ControlPlaneFight: the same key keeps coming back, so whoever owns this
	// table disagrees with the log about who belongs on the network.
	ControlPlaneFight = "CONTROL_PLANE_FIGHT"
	// Quarantined: the configured fight policy took the interface down.
	Quarantined = "QUARANTINED"
	// QuarantineFailed: it tried, and could not.
	QuarantineFailed = "QUARANTINE_FAILED"
)

// Fight policies (`ENFORCEMENT.md` part 3).
const (
	// PolicyAlarm keeps evicting and keeps alarming. The default, because the
	// alternative disconnects a network.
	PolicyAlarm = "alarm"
	// PolicyQuarantine brings the interface down until an operator
	// intervenes. Fail-closed **by choice, never by default**.
	PolicyQuarantine = "quarantine"
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
	// Now is this node's wall clock. It is used for expiry (§5.3 `expires` is
	// written in wall time by whoever signed the entry) and for the
	// `written_at_local_clock` field -- never for freshness.
	Now func() time.Time
	// Mono is a monotonic elapsed reading. Freshness is measured with this and
	// nothing else, so a node whose wall clock is wrong, or is moved while it
	// runs, still ages its view correctly (A11, GOSSIP part 5). Defaults to
	// time since the agent started.
	Mono func() time.Duration
	// Hard is S_hard: the age past which the enforcer drops every peer. Zero
	// leaves it off, which is the default -- see freshness.Limits.
	Hard time.Duration
	// MaxSkew is Δclock: how far this machine's wall clock may be from witness
	// time before CLOCK_SKEW is raised. Zero means freshness.DefaultMaxSkew.
	MaxSkew time.Duration
	// DegradedAlarmEvery is how often a degraded view repeats its alarm.
	// Defaults to DefaultDegradedAlarmEvery.
	DegradedAlarmEvery time.Duration
	Emit               func(Event)

	// FightPolicy is what to do when the same key keeps coming back:
	// PolicyAlarm (the default) or PolicyQuarantine.
	FightPolicy string
	// FightThreshold and FightWindow override the documented 3-in-60s.
	FightThreshold int
	FightWindow    time.Duration
	// Quarantine takes the interface out of service. Required only when the
	// policy asks for it; an agent configured to quarantine with no way to do
	// it refuses to start rather than discovering it mid-incident.
	Quarantine func(reason string) error
}

// Agent runs the cycle and remembers the last state that verified.
type Agent struct {
	cfg         Config
	last        *logclient.Result
	fights      *fight.Detector
	quarantined bool
	// clock remembers the newest instant any quorum vouched for. It is the
	// node's only clock for deciding whether what it holds is current.
	clock freshness.Clock
	// staleState is the freshness state last reported, and staleSince the
	// monotonic reading of the last `degraded` alarm -- together they are the
	// alarm cadence.
	staleState string
	staleSince time.Duration
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
	if cfg.DegradedAlarmEvery <= 0 {
		cfg.DegradedAlarmEvery = DefaultDegradedAlarmEvery
	}
	if cfg.Mono == nil {
		// time.Since carries Go's monotonic reading, which does not move when
		// the wall clock is set. That is the whole point: the default must be
		// a clock the operator cannot accidentally change.
		started := time.Now()
		cfg.Mono = func() time.Duration { return time.Since(started) }
	}
	if cfg.Emit == nil {
		cfg.Emit = func(Event) {}
	}
	switch cfg.FightPolicy {
	case "":
		cfg.FightPolicy = PolicyAlarm
	case PolicyAlarm:
	case PolicyQuarantine:
		if cfg.Quarantine == nil {
			return nil, errors.New("agent: the quarantine policy needs a way to take the " +
				"interface out of service; finding that out mid-incident is too late")
		}
	default:
		return nil, fmt.Errorf("agent: %q is not a fight policy; use %q or %q",
			cfg.FightPolicy, PolicyAlarm, PolicyQuarantine)
	}
	return &Agent{cfg: cfg,
		fights: fight.New(cfg.FightThreshold, cfg.FightWindow)}, nil
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
		Policy:  a.cfg.Anchor.Policy,
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

	// Witness time advances only on a checkpoint that actually verified; a
	// head this node refused says nothing about what time it is. This comes
	// before reconciling because how old the view is decides what reconciling
	// is allowed to do.
	if verifyErr == nil && result.QuorumTime != nil {
		a.clock.Observe(*result.QuorumTime, a.cfg.Mono())
		a.checkClock(*result.QuorumTime, result.State.Params)
	}
	fresh := a.freshness(result)
	a.reportFreshness(fresh)

	if err := a.reconcile(result, fresh); err != nil {
		return err
	}

	if verifyErr == nil && a.cfg.RunDir != "" {
		set, err := proven.FromResult(result, a.cfg.Now(), fresh)
		if err != nil {
			return err
		}
		if err := proven.Write(a.cfg.RunDir, set, result); err != nil {
			return err
		}
	}
	return verifyErr
}

// reportFreshness says what state the view is in, on the cadence GOSSIP part 5
// asks for.
//
// `degraded` is loud by design, but a daemon polling every minute must not
// produce a page a minute -- and a degraded node that simply went quiet would
// be indistinguishable from one that recovered. So it repeats every
// DegradedAlarmEvery for as long as it lasts, and recovering resets the
// cadence: the next degradation is announced at once, not five minutes later.
func (a *Agent) reportFreshness(fresh proven.Freshness) {
	mono := a.cfg.Mono()
	switch fresh.State {
	case freshness.HardStale:
		if a.staleState != freshness.HardStale {
			a.emit(Event{Kind: HardStale, Message: fmt.Sprintf(
				"the view is %s old and nothing newer has been cosigned; dropping "+
					"every peer, because past this age enforcing it would be a guess",
				roundAge(fresh.Age))})
		}
	case freshness.Degraded:
		if a.staleState != freshness.Degraded || mono-a.staleSince >= a.cfg.DegradedAlarmEvery {
			a.emit(Event{Kind: Degraded, Message: fmt.Sprintf(
				"the view is %s old; keeping the peer table, because a quiet log is "+
					"not evidence that a peer stopped being proven",
				roundAge(fresh.Age))})
			a.staleSince = mono
		}
	}
	if fresh.State != a.staleState {
		a.staleState = fresh.State
		if fresh.State == freshness.Degraded {
			a.staleSince = mono
		}
	}
}

// roundAge renders an age for a human, or says it is unknown.
func roundAge(age *time.Duration) string {
	if age == nil {
		return "of unknown age"
	}
	return age.Round(time.Second).String()
}

// reconcile turns a verified state into peer-table actions.
//
// Past S_hard the desired set is **empty**, which is exactly `GOSSIP.md` part
// 5's "owner: ReplacePeers []; watchdog: evict all" -- the existing reconciler
// already does both for an empty set, so hard-stale needs no second code path
// that could disagree with the first.
func (a *Agent) reconcile(result *logclient.Result, fresh proven.Freshness) error {
	desired, report := a.desired(result)
	if fresh.State == freshness.HardStale {
		desired, report = nil, endpoint.Report{}
	}
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
	if err := reconcile.Apply(a.cfg.Device, plan); err != nil {
		return err
	}
	a.noteEvictions(plan)
	return nil
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

// noteEvictions watches for the same key being put back over and over.
//
// Evictions are recorded only after they succeeded: a key Norn failed to
// remove has not come back, and counting it would turn a broken interface into
// an accusation against the control plane.
func (a *Agent) noteEvictions(plan reconcile.Plan) {
	now := a.cfg.Now()
	for _, key := range plan.Remove {
		count, started := a.fights.Record(key, now)
		if !started {
			continue
		}
		a.emit(Event{Kind: ControlPlaneFight,
			Message: fmt.Sprintf("%s has been evicted %d times in %s: whoever owns this "+
				"peer table disagrees with the log", key.Short(), count, a.fights.Window()),
			Peer: &reconcile.Alarm{Kind: ControlPlaneFight, Key: key}})
		a.applyFightPolicy(key)
	}
}

// applyFightPolicy does what the operator chose, once.
func (a *Agent) applyFightPolicy(key peertable.Key) {
	if a.cfg.FightPolicy != PolicyQuarantine || a.quarantined {
		return
	}
	reason := fmt.Sprintf("control plane fight over %s", key.Short())
	if err := a.cfg.Quarantine(reason); err != nil {
		a.emit(Event{Kind: QuarantineFailed, Message: err.Error()})
		return
	}
	a.quarantined = true
	a.emit(Event{Kind: Quarantined,
		Message: "the interface has been taken out of service until an operator intervenes (" +
			reason + ")"})
}

// Quarantined reports whether the fight policy has fired.
func (a *Agent) Quarantined() bool { return a.quarantined }

func (a *Agent) emit(event Event) { a.cfg.Emit(event) }

// keyOf converts the hex key §5.3 stores into the one the peer table uses.
func keyOf(hexKey string) (peertable.Key, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return peertable.Key{}, err
	}
	return peertable.KeyFromBytes(raw)
}

// checkClock compares this machine's wall clock against witness time and
// alarms if they disagree by more than Δclock.
//
// This runs on the direct-from-log path only, which today is the only path
// there is. When gossip arrives (4.5) a checkpoint pulled from a peer must
// *not* come through here: a peer may legitimately be serving an older head,
// and its age is the peer's business rather than evidence about this machine's
// clock.
//
// The alarm is all that happens. Nothing downstream reads it, by design: a
// node that changed what it enforced because of its own clock would be doing
// the exact thing A11 forbids.
func (a *Agent) checkClock(quorumTime time.Time, params map[string]any) {
	limits := freshness.LimitsFrom(params, a.cfg.Hard)
	limits.MaxSkew = a.cfg.MaxSkew

	skew, ok := a.clock.Skew(quorumTime, a.cfg.Mono(), a.cfg.Now())
	if !ok || !limits.SkewIsSignificant(skew) {
		return
	}
	a.emit(Event{Kind: ClockSkew, Message: fmt.Sprintf(
		"this machine's clock is %s from witness time; nothing about what this "+
			"node enforces has changed, but the clock should be fixed",
		skew.Round(time.Second))})
}

// freshness is how old the view this node is enforcing has become, in witness
// time. The checkpoint being enforced may be older than the newest the node
// has seen -- it holds the last one that verified -- so the age is read for
// *that* checkpoint rather than for the best one known.
func (a *Agent) freshness(result *logclient.Result) proven.Freshness {
	limits := freshness.LimitsFrom(result.State.Params, a.cfg.Hard)
	if result.QuorumTime == nil {
		return proven.View(&a.clock, limits, time.Time{}, a.cfg.Mono())
	}
	return proven.View(&a.clock, limits, *result.QuorumTime, a.cfg.Mono())
}
