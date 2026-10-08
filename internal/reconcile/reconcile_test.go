package reconcile

import (
	"net/netip"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/peertable"
)

func key(t *testing.T, b byte) peertable.Key {
	t.Helper()
	var k peertable.Key
	for i := range k {
		k[i] = b
	}
	return k
}

func peer(t *testing.T, b byte, cidr string) peertable.Peer {
	t.Helper()
	return peertable.Peer{Key: key(t, b), AllowedIPs: []netip.Prefix{netip.MustParsePrefix(cidr)}}
}

func kinds(plan Plan) map[string]int {
	out := map[string]int{}
	for _, alarm := range plan.Alarms {
		out[alarm.Kind]++
	}
	return out
}

// Observe never writes. That is its entire contract (D-005), and the gate
// measures it over 24 hours; here it is a type-level fact.
func TestObserveNeverWrites(t *testing.T) {
	legit := peer(t, 1, "10.9.0.1/32")
	rogue := peer(t, 9, "10.9.0.9/32")
	missing := peer(t, 2, "10.9.0.2/32")

	plan := Decide(Observe, []peertable.Peer{legit, rogue}, []peertable.Peer{legit, missing})

	if plan.WritesAnything() {
		t.Fatalf("observe planned a write: %+v", plan)
	}
	got := kinds(plan)
	if got[UnprovenPeer] != 1 || got[MissingPeer] != 1 {
		t.Errorf("alarms = %v, want one unproven and one missing", got)
	}
	for _, alarm := range plan.Alarms {
		if alarm.Kind == UnprovenPeer && alarm.Key != rogue.Key {
			t.Error("the unproven alarm names the wrong key")
		}
	}
}

// An alarm has to carry what the key was given, or an operator cannot tell a
// stray peer from a routing hijack.
func TestAnUnprovenAlarmCarriesWhatTheKeyWasGiven(t *testing.T) {
	rogue := peer(t, 9, "0.0.0.0/0")
	rogue.Endpoint = netip.MustParseAddrPort("192.0.2.66:51820")

	plan := Decide(Observe, []peertable.Peer{rogue}, nil)
	if len(plan.Alarms) != 1 {
		t.Fatalf("alarms = %+v", plan.Alarms)
	}
	alarm := plan.Alarms[0]
	if len(alarm.AllowedIPs) != 1 || alarm.AllowedIPs[0].String() != "0.0.0.0/0" {
		t.Errorf("the alarm omits the allowed-ips: %+v", alarm)
	}
	if alarm.Endpoint != rogue.Endpoint {
		t.Errorf("the alarm omits the endpoint: %+v", alarm)
	}
}

func TestOwnerReplacesWhenTheKeysDiffer(t *testing.T) {
	legit := peer(t, 1, "10.9.0.1/32")
	rogue := peer(t, 9, "10.9.0.9/32")

	plan := Decide(Owner, []peertable.Peer{legit, rogue}, []peertable.Peer{legit})
	if plan.Replace == nil {
		t.Fatal("owner mode did not rewrite the table")
	}
	if len(plan.Replace) != 1 || plan.Replace[0].Key != legit.Key {
		t.Errorf("replace = %+v, want only the proven peer", plan.Replace)
	}
	if kinds(plan)[UnprovenPeer] != 1 {
		t.Error("evicting an intruder silently would hide the attack it is evidence of")
	}
}

func TestOwnerCarriesPresharedKeysThroughARewrite(t *testing.T) {
	wanted := peer(t, 1, "10.9.0.1/32")
	wanted.Endpoint = netip.MustParseAddrPort("192.0.2.1:51820")
	current := wanted
	current.PresharedKey[0] = 7
	fake := peertable.NewFake(current, peer(t, 9, "10.9.0.9/32"))
	actual, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	plan := Decide(Owner, actual, []peertable.Peer{wanted})
	if len(plan.Replace) != 1 {
		t.Fatal("the rogue peer must force a full replacement")
	}
	if plan.Replace[0].PresharedKey != current.PresharedKey {
		t.Error("owner rewrite discarded the operator's preshared key")
	}
	if err := Apply(fake, plan); err != nil {
		t.Fatal(err)
	}
	installed, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(installed) != 1 || installed[0].PresharedKey != current.PresharedKey {
		t.Error("the rewritten table lost the preshared key")
	}
}

// The hijack that keeps a proven key: the control plane leaves the key alone
// and widens its allowed-ips to everything.
func TestOwnerReplacesWhenAllowedIPsWiden(t *testing.T) {
	proven := peer(t, 1, "10.9.0.1/32")
	widened := peer(t, 1, "0.0.0.0/0")

	plan := Decide(Owner, []peertable.Peer{widened}, []peertable.Peer{proven})
	if plan.Replace == nil {
		t.Fatal("a widened allowed-ips is a routing change and must be corrected")
	}
	if plan.Replace[0].AllowedIPs[0].String() != "10.9.0.1/32" {
		t.Errorf("replace did not restore the proven routes: %+v", plan.Replace)
	}
}

// Nothing to do must mean no write at all: owner mode runs every T_poll, and a
// table it rewrites each time is a table nobody can diff for 24 hours.
func TestOwnerIsQuietWhenTheTableIsRight(t *testing.T) {
	one := peer(t, 1, "10.9.0.1/32")
	two := peer(t, 2, "10.9.0.2/32")

	plan := Decide(Owner, []peertable.Peer{one, two}, []peertable.Peer{two, one})
	if plan.WritesAnything() {
		t.Fatalf("owner rewrote a table that was already right: %+v", plan)
	}
	if len(plan.Alarms) != 0 {
		t.Errorf("alarms on a healthy table: %+v", plan.Alarms)
	}
}

// An endpoint change is a refresh, not a rewrite: UpdateOnly exists for it.
func TestOwnerUpdatesEndpointsWithoutRewriting(t *testing.T) {
	proven := peer(t, 1, "10.9.0.1/32")
	proven.Endpoint = netip.MustParseAddrPort("192.0.2.1:51820")
	proven.Keepalive = 25 * time.Second

	stale := proven
	stale.Endpoint = netip.MustParseAddrPort("198.51.100.7:51820")

	plan := Decide(Owner, []peertable.Peer{stale}, []peertable.Peer{proven})
	if plan.Replace != nil {
		t.Error("an endpoint change must not rewrite the whole table")
	}
	if len(plan.Update) != 1 || plan.Update[0].Endpoint != proven.Endpoint {
		t.Errorf("update = %+v", plan.Update)
	}
}

// The one that matters for a roaming peer: the provider knows no endpoint, the
// interface has learned one from a handshake. Rewriting with a zero endpoint
// would throw that away and knock the peer offline until it handshakes again.
func TestOwnerKeepsALearnedEndpointWhenTheProviderHasNone(t *testing.T) {
	proven := peer(t, 1, "10.9.0.1/32") // no endpoint from the provider
	learned := proven
	learned.Endpoint = netip.MustParseAddrPort("203.0.113.5:51820")
	rogue := peer(t, 9, "10.9.0.9/32")

	plan := Decide(Owner, []peertable.Peer{learned, rogue}, []peertable.Peer{proven})
	if plan.Replace == nil {
		t.Fatal("the rogue key should have forced a rewrite")
	}
	for _, p := range plan.Replace {
		if p.Key == proven.Key && p.Endpoint != learned.Endpoint {
			t.Errorf("the rewrite discarded a learned endpoint: %+v", p)
		}
	}
}

func TestWatchdogRemovesOnlyTheUnproven(t *testing.T) {
	legit := peer(t, 1, "10.9.0.1/32")
	rogue := peer(t, 9, "10.9.0.9/32")
	absent := peer(t, 2, "10.9.0.2/32")

	plan := Decide(Watchdog, []peertable.Peer{legit, rogue},
		[]peertable.Peer{legit, absent})

	if plan.Replace != nil {
		t.Error("watchdog mode does not own the table and must not rewrite it")
	}
	if len(plan.Remove) != 1 || plan.Remove[0] != rogue.Key {
		t.Errorf("remove = %+v, want only the unproven key", plan.Remove)
	}
	got := kinds(plan)
	if got[EvictedPeer] != 1 {
		t.Errorf("an eviction must be alarmed: %v", got)
	}
	// A proven peer the other writer has not installed is the control plane's
	// business, not Norn's (G4 non-goal) -- reported, never installed.
	if got[MissingPeer] != 1 {
		t.Errorf("a missing proven peer should be reported: %v", got)
	}
}

// ENFORCEMENT.md's A1 check, as a test rather than a paragraph: the control
// plane installs the attacker's key with the legitimate device's routes and
// removes the legitimate key.
func TestTheSwapAttack(t *testing.T) {
	legit := peer(t, 1, "10.9.0.1/32")
	attacker := peertable.Peer{Key: key(t, 9), AllowedIPs: legit.AllowedIPs}

	owner := Decide(Owner, []peertable.Peer{attacker}, []peertable.Peer{legit})
	if owner.Replace == nil || len(owner.Replace) != 1 || owner.Replace[0].Key != legit.Key {
		t.Fatalf("owner mode must evict the attacker and restore the device: %+v", owner)
	}
	if kinds(owner)[UnprovenPeer] != 1 {
		t.Error("the attempt must be visible, not merely corrected")
	}

	watchdog := Decide(Watchdog, []peertable.Peer{attacker}, []peertable.Peer{legit})
	if len(watchdog.Remove) != 1 || watchdog.Remove[0] != attacker.Key {
		t.Fatalf("watchdog must evict the attacker: %+v", watchdog)
	}
	// And it must NOT install the legitimate peer: availability belongs to
	// whoever owns the table. Saying so in a test keeps it a decision.
	if watchdog.Replace != nil || len(watchdog.Update) != 0 {
		t.Error("watchdog mode installed a peer; availability is not its job")
	}
	if kinds(watchdog)[MissingPeer] != 1 {
		t.Error("the absent device should still be reported")
	}
}

func TestAnUnknownModeIsRefused(t *testing.T) {
	plan := Decide(Mode("enforce"), nil, nil)
	if !plan.Invalid {
		t.Fatal("an unknown mode must not silently do nothing")
	}
	if plan.WritesAnything() {
		t.Error("an unknown mode planned a write")
	}
}

func TestApplyPerformsExactlyThePlan(t *testing.T) {
	legit := peer(t, 1, "10.9.0.1/32")
	rogue := peer(t, 9, "10.9.0.9/32")

	fake := peertable.NewFake(legit, rogue)
	plan := Decide(Watchdog, []peertable.Peer{legit, rogue}, []peertable.Peer{legit})
	if err := Apply(fake, plan); err != nil {
		t.Fatal(err)
	}
	if len(fake.Calls) != 1 || fake.Calls[0].Op != "remove" {
		t.Fatalf("calls = %+v, want one remove", fake.Calls)
	}
	peers, _ := fake.Peers()
	if len(peers) != 1 || peers[0].Key != legit.Key {
		t.Errorf("table = %+v", peers)
	}
}

func TestApplyDoesNothingForObserve(t *testing.T) {
	rogue := peer(t, 9, "10.9.0.9/32")
	fake := peertable.NewFake(rogue)

	if err := Apply(fake, Decide(Observe, []peertable.Peer{rogue}, nil)); err != nil {
		t.Fatal(err)
	}
	if fake.Writes() != 0 {
		t.Fatalf("observe wrote to the interface: %+v", fake.Calls)
	}
}

func TestApplyReportsAFailedWrite(t *testing.T) {
	rogue := peer(t, 9, "10.9.0.9/32")
	fake := peertable.NewFake(rogue)
	fake.FailWrite = peertable.ErrDown

	err := Apply(fake, Decide(Watchdog, []peertable.Peer{rogue}, nil))
	if err == nil {
		t.Fatal("a failed eviction was reported as success")
	}
}
