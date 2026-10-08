package agent

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/endpoint"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

func vectors() string { return filepath.Join("..", "..", "testdata", "vectors") }

func anchor(t *testing.T) *trust.Trust {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// servedLog is the shipped 90-entry log, copied so a test may damage it.
func servedLog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(vectors(), "served")
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dir, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

type recorder struct{ events []Event }

func (r *recorder) emit(e Event) { r.events = append(r.events, e) }

func (r *recorder) kinds() map[string]int {
	out := map[string]int{}
	for _, e := range r.events {
		out[e.Kind]++
	}
	return out
}

func rogue(t *testing.T) peertable.Peer {
	t.Helper()
	var key peertable.Key
	for i := range key {
		key[i] = 0x9e
	}
	return peertable.Peer{Key: key}
}

// provenKeys returns the keys the shipped log proves, so a test can start the
// interface in a healthy state.
func provenKeys(t *testing.T) []peertable.Peer {
	t.Helper()
	doc := anchor(t)
	result, err := logclient.Verify(logclient.Dir(filepath.Join(vectors(), "served")),
		logclient.Anchor{Anchor: replay.Anchor{Net: doc.Net, GenesisHash: doc.GenesisHash},
			LogKeys: []string{doc.LogKey}, Policy: doc.Policy})
	if err != nil {
		t.Fatal(err)
	}
	var peers []peertable.Peer
	for _, id := range proven.Devices(result.State, time.Unix(1_760_000_000, 0)) {
		raw, err := hex.DecodeString(result.State.Devices[id].WgPk)
		if err != nil {
			t.Fatal(err)
		}
		key, err := peertable.KeyFromBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		peers = append(peers, peertable.Peer{Key: key})
	}
	return peers
}

func newAgent(t *testing.T, mode reconcile.Mode, logDir string,
	device peertable.Device, rec *recorder) *Agent {
	t.Helper()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(logDir), Device: device,
		Mode: mode, Now: func() time.Time { return time.Unix(1_760_000_000, 0) },
		Emit: rec.emit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// Observe is the default, because a mode that enforces by accident is a mode
// that takes a network down by accident (D-005).
func TestObserveIsTheDefault(t *testing.T) {
	rec := &recorder{}
	a, err := New(Config{Anchor: anchor(t), Fetcher: logclient.Dir(servedLog(t)),
		Device: peertable.NewFake(), Emit: rec.emit})
	if err != nil {
		t.Fatal(err)
	}
	if a.Mode() != reconcile.Observe {
		t.Fatalf("mode = %q with none configured", a.Mode())
	}
}

func TestObserveAlarmsAndWritesNothing(t *testing.T) {
	rec := &recorder{}
	fake := peertable.NewFake(provenKeys(t)...)
	fake.Inject(rogue(t))

	a := newAgent(t, reconcile.Observe, servedLog(t), fake, rec)
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if fake.Writes() != 0 {
		t.Fatalf("observe wrote to the interface: %+v", fake.Calls)
	}
	if rec.kinds()[reconcile.UnprovenPeer] != 1 {
		t.Errorf("events = %v, want one unproven peer", rec.kinds())
	}
}

func TestWatchdogEvictsWhatTheLogDoesNotProve(t *testing.T) {
	rec := &recorder{}
	fake := peertable.NewFake(provenKeys(t)...)
	fake.Inject(rogue(t))

	a := newAgent(t, reconcile.Watchdog, servedLog(t), fake, rec)
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	peers, _ := fake.Peers()
	for _, peer := range peers {
		if peer.Key == rogue(t).Key {
			t.Fatal("the rogue key survived a watchdog cycle")
		}
	}
	if rec.kinds()[reconcile.EvictedPeer] != 1 {
		t.Errorf("events = %v", rec.kinds())
	}
}

func TestFailedWatchdogEvictionDoesNotClaimSuccess(t *testing.T) {
	rec := &recorder{}
	fake := peertable.NewFake(provenKeys(t)...)
	fake.Inject(rogue(t))
	fake.FailWrite = peertable.ErrDown
	a := newAgent(t, reconcile.Watchdog, servedLog(t), fake, rec)
	if err := a.Once(); err == nil {
		t.Fatal("failed eviction was reported as a successful cycle")
	}
	if rec.kinds()[reconcile.UnprovenPeer] != 1 {
		t.Errorf("unproven peer not reported: %v", rec.kinds())
	}
	if rec.kinds()[reconcile.EvictedPeer] != 0 {
		t.Errorf("failed eviction was reported as completed: %v", rec.kinds())
	}
}

func TestOwnerInstallsTheProvenSet(t *testing.T) {
	rec := &recorder{}
	fake := peertable.NewFake()
	fake.Inject(rogue(t))

	a := newAgent(t, reconcile.Owner, servedLog(t), fake, rec)
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	peers, _ := fake.Peers()
	if len(peers) != len(provenKeys(t)) {
		t.Fatalf("%d peers, want the %d proven", len(peers), len(provenKeys(t)))
	}
	for _, peer := range peers {
		if peer.Key == rogue(t).Key {
			t.Fatal("the rogue key survived an owner cycle")
		}
	}
}

// The failure that matters most. A log going down is an outage of Norn's
// ability to learn new facts; it is not a reason to disconnect a network.
func TestAnUnverifiableLogNeverEmptiesTheTable(t *testing.T) {
	for _, mode := range []reconcile.Mode{reconcile.Observe, reconcile.Owner, reconcile.Watchdog} {
		t.Run(string(mode), func(t *testing.T) {
			rec := &recorder{}
			healthy := provenKeys(t)
			fake := peertable.NewFake(healthy...)
			// A log directory that is simply not there.
			a := newAgent(t, mode, filepath.Join(t.TempDir(), "gone"), fake, rec)

			if err := a.Once(); err == nil {
				t.Fatal("an unreachable log was reported as a healthy cycle")
			}
			peers, _ := fake.Peers()
			if len(peers) != len(healthy) {
				t.Fatalf("the peer table changed: %d peers, was %d", len(peers), len(healthy))
			}
			if fake.Writes() != 0 {
				t.Errorf("the interface was written to: %+v", fake.Calls)
			}
			if rec.kinds()[VerifyFailed] != 1 || rec.kinds()[NoStateYet] != 1 {
				t.Errorf("events = %v, want a verify failure and a no-state notice", rec.kinds())
			}
		})
	}
}

// Once something has verified, a later failure keeps enforcing those facts --
// so an intruder cannot wait for the log to go down.
func TestAfterALogOutageTheLastGoodStateIsStillEnforced(t *testing.T) {
	rec := &recorder{}
	logDir := servedLog(t)
	fake := peertable.NewFake(provenKeys(t)...)
	a := newAgent(t, reconcile.Watchdog, logDir, fake, rec)

	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	// The log goes away, and an intruder arrives.
	if err := os.RemoveAll(logDir); err != nil {
		t.Fatal(err)
	}
	fake.Inject(rogue(t))

	if err := a.Once(); err == nil {
		t.Fatal("a missing log was reported as a healthy cycle")
	}
	peers, _ := fake.Peers()
	for _, peer := range peers {
		if peer.Key == rogue(t).Key {
			t.Fatal("an intruder survived by waiting for the log to go down")
		}
	}
	if rec.kinds()[EnforcingOnStaleState] != 1 {
		t.Errorf("enforcing older facts must be said out loud: %v", rec.kinds())
	}
}

// A log that serves a tampered checkpoint is not a log outage -- it is worse.
// The peer table must still survive it.
func TestATamperedLogDoesNotDisturbTheTable(t *testing.T) {
	rec := &recorder{}
	logDir := servedLog(t)
	healthy := provenKeys(t)
	fake := peertable.NewFake(healthy...)

	path := filepath.Join(logDir, "checkpoint")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, []byte("tampered\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	a := newAgent(t, reconcile.Owner, logDir, fake, rec)
	if err := a.Once(); err == nil {
		t.Fatal("a tampered checkpoint verified")
	}
	peers, _ := fake.Peers()
	if len(peers) != len(healthy) || fake.Writes() != 0 {
		t.Fatalf("a tampered log changed the interface: %d peers, %d writes",
			len(peers), fake.Writes())
	}
}

func TestPublishesTheProvenSet(t *testing.T) {
	rec := &recorder{}
	runDir := t.TempDir()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(servedLog(t)),
		Device: peertable.NewFake(), Mode: reconcile.Observe, RunDir: runDir,
		Now: func() time.Time { return time.Unix(1_760_000_000, 0) }, Emit: rec.emit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}

	set, err := proven.Read(filepath.Join(runDir, proven.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Devices) == 0 {
		t.Fatal("no devices published")
	}
	// The shipped log is cosigned, so this node has a clock and publishes a
	// state rather than `unknown` -- and an age, which a consumer needs to
	// decide anything for itself.
	if set.Freshness != proven.Fresh {
		t.Errorf("freshness = %q, want %q", set.Freshness, proven.Fresh)
	}
	if set.AgeSeconds == nil {
		t.Error("a node with a witness clock must publish the age it computed")
	}
	for _, device := range set.Devices {
		if _, err := os.Stat(filepath.Join(runDir, device.Proof)); err != nil {
			t.Errorf("%s: %v", device.DeviceID, err)
		}
	}
}

// A stale publication would be worse than none: it would look current.
func TestAFailedCycleDoesNotRepublish(t *testing.T) {
	runDir := t.TempDir()
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(filepath.Join(t.TempDir(), "gone")),
		Device: peertable.NewFake(), Mode: reconcile.Observe, RunDir: runDir,
		Now: time.Now, Emit: rec.emit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err == nil {
		t.Fatal("an unreachable log verified")
	}
	if _, err := os.Stat(filepath.Join(runDir, proven.FileName)); err == nil {
		t.Error("a failed cycle published a proven set")
	}
}

// ENFORCEMENT.md part 8: a missing or invalid trust file means refuse to
// start, in every mode. Starting without one would be a node that enforces
// nothing while looking like it works.
func TestRefusesToStartWithoutAUsableAnchor(t *testing.T) {
	if _, err := New(Config{Fetcher: logclient.Dir("."), Device: peertable.NewFake()}); err == nil {
		t.Error("started with no trust file")
	}

	broken := *anchor(t)
	broken.Witnesses = nil // §9.1: a quorum nobody can reach
	_, err := New(Config{Anchor: &broken, Fetcher: logclient.Dir("."),
		Device: peertable.NewFake()})
	if err == nil {
		t.Fatal("started with an unusable anchor")
	}
	if !strings.Contains(err.Error(), "anchor") {
		t.Errorf("err = %v", err)
	}
}

func TestAnUnreadableInterfaceIsAnError(t *testing.T) {
	rec := &recorder{}
	fake := peertable.NewFake()
	fake.FailPeers = peertable.ErrDown

	a := newAgent(t, reconcile.Owner, servedLog(t), fake, rec)
	if err := a.Once(); err == nil {
		t.Fatal("a cycle succeeded without reading the interface")
	}
	if rec.kinds()[InterfaceUnavailable] != 1 {
		t.Errorf("events = %v", rec.kinds())
	}
}

// A provider with opinions about devices the log does not prove is reported,
// because a control plane quietly trying to add peers is the event worth
// seeing.
func TestProviderClaimsAreReported(t *testing.T) {
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(servedLog(t)),
		Device: peertable.NewFake(), Mode: reconcile.Observe,
		Provider: endpoint.Static{Peers: map[string]endpoint.Hints{"ghost": {}}},
		Now:      func() time.Time { return time.Unix(1_760_000_000, 0) }, Emit: rec.emit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	var sawGhost bool
	for _, event := range rec.events {
		if event.Kind == ProviderClaim && strings.Contains(event.Message, "ghost") {
			sawGhost = true
		}
	}
	if !sawGhost {
		t.Errorf("the provider's claim about an unproven device was not reported: %v", rec.kinds())
	}
}

// A control plane that keeps putting a key back is not misconfigured, it is
// disagreeing -- and one eviction at a time the two look identical.
func TestAControlPlaneThatKeepsComingBackIsNamed(t *testing.T) {
	rec := &recorder{}
	fake := peertable.NewFake(provenKeys(t)...)
	a := newAgent(t, reconcile.Watchdog, servedLog(t), fake, rec)

	for i := 0; i < 3; i++ {
		fake.Inject(rogue(t)) // the other writer puts it back
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
	}
	if rec.kinds()[ControlPlaneFight] != 1 {
		t.Fatalf("events = %v, want exactly one fight declared", rec.kinds())
	}
	if rec.kinds()[reconcile.EvictedPeer] != 3 {
		t.Errorf("all three evictions should still be reported: %v", rec.kinds())
	}
	// And it keeps evicting: alarming is not giving up.
	peers, _ := fake.Peers()
	for _, peer := range peers {
		if peer.Key == rogue(t).Key {
			t.Fatal("Norn stopped evicting once it declared a fight")
		}
	}
}

// Failing closed is a choice. The default keeps a network up.
func TestQuarantineNeverHappensByDefault(t *testing.T) {
	rec := &recorder{}
	fake := peertable.NewFake(provenKeys(t)...)
	a := newAgent(t, reconcile.Watchdog, servedLog(t), fake, rec)

	for i := 0; i < 5; i++ {
		fake.Inject(rogue(t))
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
	}
	if a.Quarantined() {
		t.Fatal("a default configuration took the interface down")
	}
	if rec.kinds()[Quarantined] != 0 {
		t.Errorf("events = %v", rec.kinds())
	}
}

func TestQuarantineFiresOnceWhenChosen(t *testing.T) {
	rec := &recorder{}
	fake := peertable.NewFake(provenKeys(t)...)
	var calls []string
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(servedLog(t)), Device: fake,
		Mode: reconcile.Watchdog, FightPolicy: PolicyQuarantine,
		Quarantine: func(reason string) error { calls = append(calls, reason); return nil },
		Now:        func() time.Time { return time.Unix(1_760_000_000, 0) }, Emit: rec.emit,
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 6; i++ {
		fake.Inject(rogue(t))
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("quarantine ran %d times; it must fire once, not every poll", len(calls))
	}
	if !strings.Contains(calls[0], rogue(t).Key.Short()) {
		t.Errorf("the reason should name the key: %q", calls[0])
	}
	if !a.Quarantined() || rec.kinds()[Quarantined] != 1 {
		t.Errorf("events = %v", rec.kinds())
	}
}

// An agent told to quarantine with no way to do it must say so at startup, not
// discover it in the middle of an incident.
func TestQuarantineWithoutAWayToDoItIsRefused(t *testing.T) {
	_, err := New(Config{Anchor: anchor(t), Fetcher: logclient.Dir("."),
		Device: peertable.NewFake(), FightPolicy: PolicyQuarantine})
	if err == nil {
		t.Fatal("accepted a quarantine policy with no quarantine")
	}
	if !strings.Contains(err.Error(), "mid-incident") {
		t.Errorf("err = %v", err)
	}
}

func TestAnUnknownFightPolicyIsRefused(t *testing.T) {
	_, err := New(Config{Anchor: anchor(t), Fetcher: logclient.Dir("."),
		Device: peertable.NewFake(), FightPolicy: "shutdown"})
	if err == nil {
		t.Fatal("accepted a fight policy that does not exist")
	}
}

// A failed eviction is a broken interface, not an accusation: counting it
// would blame a control plane for Norn's own inability to write.
func TestAFailedEvictionIsNotEvidenceOfAFight(t *testing.T) {
	rec := &recorder{}
	fake := peertable.NewFake(provenKeys(t)...)
	fake.Inject(rogue(t))
	fake.FailWrite = peertable.ErrDown

	a := newAgent(t, reconcile.Watchdog, servedLog(t), fake, rec)
	for i := 0; i < 5; i++ {
		if err := a.Once(); err == nil {
			t.Fatal("a failing interface reported success")
		}
	}
	if rec.kinds()[ControlPlaneFight] != 0 {
		t.Errorf("a broken interface was blamed on the control plane: %v", rec.kinds())
	}
}

// The interface is a proven device, but it cannot be its own peer. Its
// provider hints are neither unproven claims nor routes for another peer.
func TestTheOwnKeyIsNotAPeerButIsStillProven(t *testing.T) {
	for _, ownHints := range []bool{false, true} {
		t.Run(fmt.Sprint(ownHints), func(t *testing.T) {
			fake := peertable.NewFake()
			own := keyOfDevice(t, "nas")
			fake.OwnPublicKey = own
			rec := &recorder{}
			a := newAgent(t, reconcile.Owner, servedLog(t), fake, rec)
			a.cfg.RunDir = t.TempDir()
			provider := endpoint.Static{Peers: map[string]endpoint.Hints{
				"pi-cam": {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}},
				"ghost":  {},
			}}
			if ownHints {
				// This local subnet overlaps the remote host. A local device
				// must not compete in peer routing or produce an overlap alarm.
				provider.Peers["nas"] = endpoint.Hints{AllowedIPs: []netip.Prefix{
					netip.MustParsePrefix("10.9.0.1/24")}}
			}
			a.cfg.Provider = provider
			if err := a.Once(); err != nil {
				t.Fatal(err)
			}
			desired, _ := a.desired(a.last, own)
			if holds(desired, own) {
				t.Error("the interface's own key entered the desired set")
			}
			if addresses := a.PeerAddresses(8090); len(addresses) != 1 || addresses[0] != "http://10.9.0.2:8090" {
				t.Errorf("gossip addresses = %v, want only the remote peer", addresses)
			}
			set, err := proven.Read(filepath.Join(a.cfg.RunDir, proven.FileName))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, device := range set.Devices {
				if device.WgPk == own.String() {
					found = true
				}
			}
			if !found || len(set.Devices) != len(provenKeys(t)) {
				t.Error("excluding a self-peer changed what proven reports")
			}
			ghost := false
			for _, e := range rec.events {
				if (e.Peer != nil && e.Peer.Key == own) ||
					(e.Kind == ProviderClaim && strings.Contains(e.Message, `"nas"`)) ||
					(e.Kind == ProviderClaim && strings.Contains(e.Message, "overlapping")) {
					t.Errorf("the proven local device caused an alarm: %+v", e)
				}
				ghost = ghost || (e.Kind == ProviderClaim && strings.Contains(e.Message, `"ghost"`))
			}
			if !ghost {
				t.Error("suppressing local hints also suppressed an unproven provider claim")
			}
		})
	}
}

func TestAnUnmaskedHintReachesTheTableMasked(t *testing.T) {
	fake := peertable.NewFake() // No kernel masking to conceal an unnormalised write.
	a := newAgent(t, reconcile.Owner, servedLog(t), fake, &recorder{})
	a.cfg.Provider = endpoint.Static{Peers: map[string]endpoint.Hints{
		"pi-cam": {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.5/24")}},
	}}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	peers, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	got := peertable.ByKey(peers)[keyOfDevice(t, "pi-cam")].AllowedIPs
	if len(got) != 1 || got[0].String() != "10.9.0.0/24" {
		t.Errorf("table received %v, want [10.9.0.0/24]", got)
	}
}

func TestAnInterfaceWithoutAnOwnKeyStillReconcilesAndSaysSo(t *testing.T) {
	fake := peertable.NewFake()
	rec := &recorder{}
	a := newAgent(t, reconcile.Owner, servedLog(t), fake, rec)
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	peers, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != len(provenKeys(t)) || fake.Writes() != 1 {
		t.Fatalf("unconfigured interface got %d peers and %d writes", len(peers), fake.Writes())
	}
	if rec.kinds()["INTERFACE_UNCONFIGURED"] != 1 || rec.kinds()[InterfaceUnavailable] != 0 {
		t.Errorf("an absent own key must be reported without treating the interface as down: %v", rec.kinds())
	}
	for _, e := range rec.events {
		if e.Kind == "INTERFACE_UNCONFIGURED" && !strings.Contains(e.Message, "all proven devices as peers") {
			t.Errorf("the notice did not explain what the node did: %q", e.Message)
		}
	}
	// Configuring the interface later must take effect without a restart.
	fake.OwnPublicKey = keyOfDevice(t, "nas")
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	peers, _ = fake.Peers()
	if holds(peers, fake.OwnPublicKey) {
		t.Error("the newly configured own key remained a peer")
	}
}

// An interface with no key is a state, not an event: it is said when the node
// finds it so, and again only if it leaves and comes back. Said every T_poll --
// and every time gossip asks where its peers are -- it would bury everything
// else the log says.
func TestAnUnconfiguredInterfaceIsSaidOnceNotEveryPoll(t *testing.T) {
	fake := peertable.NewFake()
	rec := &recorder{}
	a := newAgent(t, reconcile.Owner, servedLog(t), fake, rec)
	for i := 0; i < 50; i++ {
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
		a.PeerAddresses(8090)
	}
	if got := rec.kinds()[InterfaceUnconfigured]; got != 1 {
		t.Fatalf("fifty cycles on an unconfigured interface said so %d times, want once", got)
	}
	fake.OwnPublicKey = keyOfDevice(t, "nas")
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	fake.OwnPublicKey = peertable.Key{}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := rec.kinds()[InterfaceUnconfigured]; got != 2 {
		t.Errorf("an interface that lost its key again was said %d times in all, want twice", got)
	}
}

type unreadableOwnKey struct{ *peertable.Fake }

func (f unreadableOwnKey) OwnKey() (peertable.Key, error) {
	return peertable.Key{}, peertable.ErrDown
}

func TestAnUnreadableOwnKeyLeavesTheTableUntouched(t *testing.T) {
	fake := peertable.NewFake(rogue(t))
	rec := &recorder{}
	a := newAgent(t, reconcile.Owner, servedLog(t), unreadableOwnKey{fake}, rec)
	a.cfg.Provider = endpoint.Static{Peers: map[string]endpoint.Hints{
		"pi-cam": {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}},
	}}
	if err := a.Once(); err == nil {
		t.Error("a failed own-key read was treated as an unconfigured interface")
	}
	if fake.Writes() != 0 || rec.kinds()[InterfaceUnavailable] == 0 {
		t.Errorf("failed own-key read: %d writes, events %v", fake.Writes(), rec.kinds())
	}
	if got := a.PeerAddresses(8090); len(got) != 0 {
		t.Errorf("gossip used an unknown local identity: %v", got)
	}
}
