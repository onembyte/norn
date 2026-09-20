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
	"math/rand"
	"path/filepath"
	"time"

	"github.com/onembyte/norn/internal/endpoint"
	"github.com/onembyte/norn/internal/fight"
	"github.com/onembyte/norn/internal/freshness"
	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/mirror"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
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
	// MirrorFailed: this node could not keep a copy of the log it verified, so
	// it has nothing to serve its peers. Nothing it enforces is affected.
	MirrorFailed = "MIRROR_FAILED"
	// AdoptedFromPeer: this node could not reach the log and took a checkpoint
	// from a peer instead. It is worth saying out loud -- the log being
	// unreachable is news even when gossip covered for it.
	AdoptedFromPeer = "ADOPTED_FROM_PEER"
	// PeerRefused: one peer could not be used this round. Not an outage -- the
	// point of asking several is that any of them may be broken, behind, or
	// lying.
	PeerRefused = "PEER_REFUSED"
)

// DefaultDegradedAlarmEvery is GOSSIP part 5's "alarm every 5 min".
const DefaultDegradedAlarmEvery = 5 * time.Minute

// DefaultGossipEvery is T_g, the interval a node asks its peers on. It is not
// the poll interval: polling the peer table four times a second is cheap and
// local, while asking three neighbours over the tunnel that often is neither.
const DefaultGossipEvery = 30 * time.Second

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
	// Peers returns the gossip addresses of this network's **proven** peers,
	// re-evaluated each cycle because the proven set changes. An unproven peer
	// is not somebody this network vouches for, so it is never asked
	// (GOSSIP part 6).
	//
	// Nil means this node does not gossip, which is the correct configuration
	// for a node alone on its tunnel.
	Peers func() []string
	// Fanout is `r`: how many peers to ask per round. Defaults to
	// gossip.DefaultFanout.
	Fanout int
	// GossipEvery is T_g: how often to ask peers whether anybody has proved a
	// fork. Unlike checkpoint gossip it runs whatever the log is doing, so it
	// has its own interval rather than the poll's. Defaults to
	// DefaultGossipEvery.
	GossipEvery time.Duration
	Emit        func(Event)

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
	// frozen means this node has proof its log forked and will accept nothing
	// further under this anchor (§11). frozenBy names the evidence.
	frozen   bool
	frozenBy string
	// evidenceAsked is the monotonic reading of the last evidence round.
	evidenceAsked time.Duration
	// peerOrder decides which peers get asked, and is a node's own so two
	// nodes started together do not walk the mesh in step.
	peerOrder *rand.Rand
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
	if cfg.GossipEvery <= 0 {
		cfg.GossipEvery = DefaultGossipEvery
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
	agent := &Agent{cfg: cfg,
		fights: fight.New(cfg.FightThreshold, cfg.FightWindow),
		// Each node walks the mesh in its own order, so two nodes started
		// together do not ask the same peers at the same moments.
		peerOrder: rand.New(rand.NewSource(time.Now().UnixNano()))}
	// A fork this node proved earlier outlives the process (§11).
	agent.loadFreeze()
	return agent, nil
}

// Mode reports the mode this agent runs in.
func (a *Agent) Mode() reconcile.Mode { return a.cfg.Mode }

// Once verifies the log and reconciles the interface with it.
//
// It returns an error when the cycle could not do its job, having already done
// whatever was safe: an error here means "this cycle learned nothing", never
// "the peer table has been abandoned".
func (a *Agent) Once() error {
	// The head this node already holds goes with every request: §10 requires a
	// new checkpoint to be at least as large and to contain it, and a node
	// that forgot to say what it holds would accept a correctly signed,
	// correctly cosigned view of its own past -- un-revoking whoever was
	// revoked since.
	var stored *tlog.Checkpoint
	var heldTree *tlog.Tree
	if a.last != nil {
		held := a.last.Checkpoint
		stored, heldTree = &held, a.last.Tree
	}
	anchor := logclient.Anchor{
		Anchor:  replay.Anchor{Net: a.cfg.Anchor.Net, GenesisHash: a.cfg.Anchor.GenesisHash},
		LogKeys: []string{a.cfg.Anchor.LogKey},
		Policy:  a.cfg.Anchor.Policy,
		Stored:  stored,
		Held:    heldTree,
	}
	// §11 duty 4: a node that has proved its log forked accepts nothing
	// further. Not the forked log, and not the original either -- it has
	// evidence that this log signs whatever suits it, and "it looks fine
	// again" is not a reason to believe it.
	if a.frozen {
		a.emit(Event{Kind: Frozen, Message: fmt.Sprintf(
			"refusing every checkpoint: this node holds proof that its log forked "+
				"(%s). The peer table is left exactly as it is. Only a new trust "+
				"file clears this (§11).", a.frozenBy)})
		return errors.New("agent: frozen by a proven fork; the interface is untouched")
	}

	result, verifyErr := logclient.Verify(a.cfg.Fetcher, anchor)

	// A fork is not an ordinary verification failure: it is proof the log
	// equivocated, and §11 gives a node four things to do about it.
	var fork *logclient.ForkError
	if errors.As(verifyErr, &fork) {
		a.recordFork(fork)
		return verifyErr
	}

	// Ask peers when the log could not be used at all, and also when it could
	// but what it gave is stale: `GOSSIP.md` part 5 has a degraded node poll
	// **all sources**, and the reason is T2. A log that is up and stuck
	// answers every request perfectly with something old, and only a peer can
	// say so -- asking peers solely when the log is unreachable would leave a
	// whole mesh stale behind a log that never stopped answering.
	//
	// While the view is fresh, peers are not asked at all. A node polling
	// every 200 ms that also asked three neighbours each time would put a
	// great deal of traffic on the link it is protecting, to learn nothing.
	if verifyErr != nil || a.isStale(result) {
		if fromPeer, peer := a.askPeers(anchor); fromPeer != nil &&
			(verifyErr != nil || fromPeer.Checkpoint.Size > result.Checkpoint.Size) {
			a.emit(Event{Kind: AdoptedFromPeer, Message: fmt.Sprintf(
				"took size %d from peer %s, which is signed by the same keys: %s",
				fromPeer.Checkpoint.Size, peer, whyPeer(verifyErr))})
			result, verifyErr = fromPeer, nil
		}
	}
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

	// Ask whether anybody has proved a fork this node has not seen (T1b).
	// This runs whatever the log is doing -- see pollEvidence for why that is
	// the whole point.
	a.pollEvidence()
	if a.frozen {
		return errors.New("agent: frozen by a fork a peer proved; the interface is untouched")
	}

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
		// Keep what was verified, so this node can serve it to peers rather
		// than only vouch for it (GOSSIP part 6). Every mode does this,
		// including observe: a node that only watches is exactly the one you
		// want serving the mesh, because it is the one nobody is worried
		// about. A failure here is worth reporting and not worth stopping a
		// cycle for -- enforcement does not depend on it.
		if err := mirror.Write(filepath.Join(a.cfg.RunDir, proven.MirrorDir),
			result.Checkpoint, result.SignedCheckpoint, result.Served); err != nil {
			a.emit(Event{Kind: MirrorFailed, Message: err.Error()})
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
	// The checkpoint's own time, not this machine's (§5.3, A11). This is the
	// clock that decides what goes in the peer table, so it is the last place
	// a wrong local clock should be able to reach: a fast one would evict a
	// device early, a slow one would keep an expired device, and neither would
	// say anything.
	at := proven.EvaluationTime(result)
	var devices []endpoint.Device
	for _, id := range proven.Devices(result.State, at) {
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

// Freshness is the state this node last computed, for a daemon deciding how
// hard to try. `GOSSIP.md` part 5 has a degraded node poll every source every
// 10 s, and a node that kept that state to itself would carry on at its
// leisurely poll straight through an outage.
//
// Before the first cycle it is `unknown`, which is the honest answer rather
// than `fresh`.
func (a *Agent) Freshness() string {
	if a.staleState == "" {
		return freshness.Unknown
	}
	return a.staleState
}

// isStale reports whether the view this result would give is older than the
// network's `staleness` -- the condition that makes a node reach past the log.
//
// It reads the clock without advancing it: whether to ask peers is a question
// about the head just fetched, and adopting it as "now" before deciding would
// answer it with itself.
func (a *Agent) isStale(result *logclient.Result) bool {
	if result == nil || result.QuorumTime == nil {
		return false
	}
	limits := freshness.LimitsFrom(result.State.Params, a.cfg.Hard)
	age, ok := a.clock.Age(*result.QuorumTime, a.cfg.Mono())
	return ok && limits.State(age, true) != freshness.Fresh
}

// whyPeer explains an adoption in the terms that made it happen.
func whyPeer(verifyErr error) string {
	if verifyErr != nil {
		return fmt.Sprintf("the log could not be used (%v)", verifyErr)
	}
	return "the log is answering but its head has gone stale, and this peer has a newer one"
}

// fanout is how many peers a round asks.
func (a *Agent) fanout() int {
	if a.cfg.Fanout > 0 {
		return a.cfg.Fanout
	}
	return gossip.DefaultFanout
}

// PeerAddresses is where this node's **proven** peers can be gossiped with:
// the tunnel address the log itself put in each peer's allowed-ips.
//
// Only proven peers, and the distinction is the whole point. An unproven key
// on the interface is exactly what Norn exists to notice; asking it for a
// checkpoint would be asking the intruder what the network looks like.
func (a *Agent) PeerAddresses(port int) []string {
	if a.last == nil || port <= 0 {
		return nil
	}
	desired, _ := a.desired(a.last)
	out := make([]string, 0, len(desired))
	for _, peer := range desired {
		if addr, ok := gossip.Address(peer.AllowedIPs, port); ok {
			out = append(out, addr)
		}
	}
	return out
}

// askPeers tries this network's proven peers and returns the best checkpoint
// any of them could prove, or nil.
//
// There is no gossip-specific verification here, and that is the whole design:
// a peer's answer goes through `logclient.Verify` under the same anchor as the
// log's, including §10's comparison with the head this node already holds. So
// a lying peer is exactly as dangerous as a lying log, which is to say caught.
//
// Peers are asked only when the log could not be used. A node polling every
// 200 ms that also asked three neighbours each time would put a great deal of
// traffic on the link it is protecting, to learn nothing.
func (a *Agent) askPeers(anchor logclient.Anchor) (*logclient.Result, string) {
	if a.cfg.Peers == nil {
		return nil, ""
	}
	var best *logclient.Result
	var from string
	for _, addr := range gossip.Choose(a.cfg.Peers(), a.fanout(), a.peerOrder) {
		result, err := logclient.Verify(gossip.Peer(addr), anchor)
		if err != nil {
			// A second *history* is not a broken neighbour. §11 does not care
			// which source it arrived from, and a peer is how a node learns
			// that the split-view it is not being shown exists at all --
			// which is the whole point of the first Phase 4 gate line.
			var fork *logclient.ForkError
			if errors.As(err, &fork) {
				a.recordFork(fork)
				return nil, ""
			}
			// Otherwise: one neighbour being broken, lying or behind is not
			// an outage.
			a.emit(Event{Kind: PeerRefused,
				Message: fmt.Sprintf("peer %s: %v", addr, err)})
			continue
		}
		if best == nil || result.Checkpoint.Size > best.Checkpoint.Size {
			best, from = result, addr
		}
	}
	return best, from
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
