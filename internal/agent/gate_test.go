package agent

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/endpoint"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/freshness"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlogstore"
)

// These tests are the software halves of `PLAN.md`'s Phase 3 gate. The gate
// itself is measurements -- a p99 over a thousand runs, two 24-hour soaks --
// and those belong to the lab. What does not belong to the lab is whether the
// behaviour being measured happens at all.

// fixtureCosignedAt is the instant norn-genlog has the fixture's witnesses
// cosign at; reusing it keeps a rebuilt log byte-identical to the shipped one.
const fixtureCosignedAt = 1_760_003_600

// fixtureWitnesses are the three witnesses the fixture's policy names, in the
// order it names them.
func fixtureWitnesses(t *testing.T) []cosign.Signer {
	t.Helper()
	var signers []cosign.Signer
	for _, name := range []string{"pi", "vps", "friend"} {
		signers = append(signers, cosign.Signer{
			Name: "norn-witness/" + name,
			Key:  fixtureKey(t, "witness-"+name),
		})
	}
	return signers
}

func fixtureKey(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Ed25519 map[string]struct{ Seed string } `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(keys.Ed25519[name].Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("no seed for %q", name)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// writableLog builds a log Norn can append to, holding the fixture's entries.
func writableLog(t *testing.T) (dir string, store *tlogstore.Store, entries [][]byte) {
	t.Helper()
	doc := anchor(t)
	dir = t.TempDir()
	// The fixture's anchor requires two of three witnesses (§10.1 step 7), so a
	// log built here must be corroborated exactly as the shipped one is --
	// otherwise these tests would be exercising a verifier with its quorum
	// check disabled, which is the check most worth not disabling.
	store, err := tlogstore.Open(dir, doc.Origin, fixtureKey(t, "logkey"),
		tlogstore.WithCosigner(tlogstore.CosignerFunc(
			cosign.Append(fixtureWitnesses(t), cosign.At(time.Unix(fixtureCosignedAt, 0))))))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(vectors(), "log", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Entries []struct{ Name string } `json:"entries"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, e := range manifest.Entries {
		body, err := os.ReadFile(filepath.Join(vectors(), "log", e.Name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Append(body); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, body)
	}
	return dir, store, entries
}

// storePrev reads the actual branch being extended, including prior appends.
func storePrev(t *testing.T, store *tlogstore.Store, typ, id string) *uint64 {
	t.Helper()
	var raw [][]byte
	for i := int64(0); i < store.Size(); i++ {
		b, err := store.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, b)
	}
	return replay.Replay(replay.FromTrust(anchor(t)), raw).Previous(typ, id)
}

// appendRevoke writes a real `revoke` entry, signed by the two signers the
// fixture leaves active.
func appendRevoke(t *testing.T, store *tlogstore.Store, deviceID string, after uint64) {
	t.Helper()
	doc := anchor(t)
	env := &entry.Envelope{
		Prev: storePrev(t, store, "revoke", deviceID), V: entry.Version, T: "revoke", Net: doc.Net, TS: 1_760_500_000, After: &after,
		Body: map[string]any{"device_id": deviceID, "reason": "lost"},
	}
	for _, name := range []string{"signer1", "signer3"} {
		if err := entry.Sign(env, fixtureKey(t, name), "signer"); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(raw); err != nil {
		t.Fatal(err)
	}
}

// appendEnroll writes a real `enroll` entry, signed by the two signers the
// fixture leaves active. A never-named device has no previous version (§4.4).
func appendEnroll(t *testing.T, store *tlogstore.Store, request *enrollreq.Request, after uint64) {
	t.Helper()
	doc := anchor(t)
	body, err := enrollreq.Encode(request)
	if err != nil {
		t.Fatal(err)
	}
	env := &entry.Envelope{
		V: entry.Version, T: "enroll", Net: doc.Net, TS: 1_760_500_000, After: &after,
		Body: map[string]any{"request": body},
	}
	for _, name := range []string{"signer1", "signer3"} {
		if err := entry.Sign(env, fixtureKey(t, name), "signer"); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(raw); err != nil {
		t.Fatal(err)
	}
}

func holds(peers []peertable.Peer, key peertable.Key) bool {
	for _, peer := range peers {
		if peer.Key == key {
			return true
		}
	}
	return false
}

// Gate line: "A `Revoke` entry drops the device within one checkpoint
// interval." The interval is the lab's to measure; *that it happens at all*
// was not tested until now -- every enforcement test so far started from a
// fixed proven set, so nothing showed the peer table following the log when
// the log changed underneath it.
func TestARevokeEntryEvictsTheDevice(t *testing.T) {
	for _, mode := range []reconcile.Mode{reconcile.Owner, reconcile.Watchdog} {
		t.Run(string(mode), func(t *testing.T) {
			dir, store, entries := writableLog(t)
			rec := &recorder{}
			fake := peertable.NewFake()
			a := newAgent(t, mode, dir, fake, rec)

			// Watchdog installs nothing, so the peer has to be there already:
			// somebody else owns this table.
			if mode == reconcile.Watchdog {
				fake.Inject(provenKeys(t)...)
			}
			if err := a.Once(); err != nil {
				t.Fatal(err)
			}

			target := keyOfDevice(t, "nas")
			peers, _ := fake.Peers()
			if !holds(peers, target) {
				t.Fatalf("nas is proven and not in the table: %+v", peers)
			}

			appendRevoke(t, store, "nas", uint64(len(entries)))

			if err := a.Once(); err != nil {
				t.Fatal(err)
			}
			peers, _ = fake.Peers()
			if holds(peers, target) {
				t.Fatal("a revoked device kept its place in the peer table")
			}
		})
	}
}

// Enrollment is the other half of revocation: a node learns a new device
// from the log on its next cycle, with no coordinator event to wake it up.
func TestAnEnrollEntryInstallsTheDevice(t *testing.T) {
	for _, mode := range []reconcile.Mode{reconcile.Owner, reconcile.Watchdog} {
		t.Run(string(mode), func(t *testing.T) {
			dir, store, _ := writableLog(t)
			rec := &recorder{}
			fake := peertable.NewFake()
			a := newAgent(t, mode, dir, fake, rec)

			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			wg, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			target, err := peertable.KeyFromBytes(wg.PublicKey().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			route := netip.MustParsePrefix("10.9.3.7/32")
			request, err := enrollreq.New(anchor(t).Net, "new-device", public,
				wg.PublicKey().Bytes(), 1_760_500_000, map[string]string{"ip": route.String()}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := enrollreq.Sign(request, private); err != nil {
				t.Fatal(err)
			}
			a.cfg.Provider = endpoint.Static{Peers: map[string]endpoint.Hints{
				request.DeviceID: {AllowedIPs: []netip.Prefix{route}},
			}}

			// Watchdog must remove the key before the log authorises it,
			// even when somebody else has already installed its route.
			peer := peertable.Peer{Key: target, AllowedIPs: []netip.Prefix{route}}
			if mode == reconcile.Watchdog {
				fake.Inject(peer)
			}
			if err := a.Once(); err != nil {
				t.Fatal(err)
			}
			if _, exists := a.last.State.Devices[request.DeviceID]; exists {
				t.Fatal("the fixture has already named the new device")
			}
			peers, _ := fake.Peers()
			if holds(peers, target) {
				t.Fatal("an unenrolled device is in the peer table")
			}
			evicted := rec.kinds()[reconcile.EvictedPeer]
			if mode == reconcile.Watchdog && evicted != 1 {
				t.Fatalf("events = %v, want one EVICTED_PEER before enrollment", rec.kinds())
			}

			appendEnroll(t, store, request, uint64(store.Size()))
			if mode == reconcile.Watchdog {
				fake.Inject(peer)
			}
			if err := a.Once(); err != nil {
				t.Fatal(err)
			}
			peers, _ = fake.Peers()
			if !holds(peers, target) {
				t.Fatalf("a newly enrolled device is not in the peer table; last rejection: %+v",
					a.last.State.Rejected[len(a.last.State.Rejected)-1])
			}
			for _, installed := range peers {
				if installed.Key == target && (len(installed.AllowedIPs) != 1 || installed.AllowedIPs[0] != route) {
					t.Fatalf("the enrolled device's routes = %v, want %s", installed.AllowedIPs, route)
				}
			}
			if got := rec.kinds()[reconcile.EvictedPeer]; got != evicted {
				t.Fatalf("%d new EVICTED_PEER events after enrollment", got-evicted)
			}
		})
	}
}

// keyOfDevice reads a device's WireGuard key out of the verified log.
func keyOfDevice(t *testing.T, id string) peertable.Key {
	t.Helper()
	doc := anchor(t)
	result, err := logclient.Verify(logclient.Dir(filepath.Join(vectors(), "served")),
		logclient.Anchor{Anchor: replay.FromTrust(doc), LogKeys: []string{doc.LogKey}, Policy: doc.Policy})
	if err != nil {
		t.Fatal(err)
	}
	device, ok := result.State.Devices[id]
	if !ok {
		t.Fatalf("%s is not in the fixture", id)
	}
	raw, err := hex.DecodeString(device.WgPk)
	if err != nil {
		t.Fatal(err)
	}
	key, err := peertable.KeyFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Gate lines: "the peer table equals the proven set at all times (24 h soak,
// zero divergence)" and "zero false removals". The soak is the lab's; that a
// quiet network produces a quiet daemon is testable here, and it is the
// property a 24-hour diff would actually be checking.
func TestNothingHappensWhenNothingChanges(t *testing.T) {
	dir, _, _ := writableLog(t)
	rec := &recorder{}
	fake := peertable.NewFake()
	a := newAgent(t, reconcile.Owner, dir, fake, rec)

	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	installed := fake.Writes()
	if installed != 1 {
		t.Fatalf("the first cycle made %d writes, want one", installed)
	}
	before, _ := fake.Peers()

	for i := 0; i < 50; i++ {
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
	}
	if fake.Writes() != installed {
		t.Errorf("%d further writes on an unchanged network; a table rewritten every "+
			"poll can never be diffed for zero divergence", fake.Writes()-installed)
	}
	after, _ := fake.Peers()
	if len(after) != len(before) {
		t.Fatalf("the peer set drifted: %d -> %d", len(before), len(after))
	}
	for _, peer := range before {
		if !holds(after, peer.Key) {
			t.Errorf("%s was removed with nothing having changed", peer.Key.Short())
		}
	}
}

// The kernel cannot hold its own key and canonicalises routes it stores.
// Prove the fake has those constraints before asking whether owner converges:
// otherwise removing a constraint would quietly turn this back into the old gate.
func TestNothingHappensWhenNothingChangesOnAKernelLikeInterface(t *testing.T) {
	fake := peertable.NewFake()
	own := keyOfDevice(t, "nas")
	fake.OwnPublicKey, fake.MaskPrefixes = own, true
	unmasked := netip.MustParsePrefix("10.9.0.5/24")
	probe := rogue(t)
	probe.AllowedIPs = []netip.Prefix{unmasked}
	if err := fake.Replace([]peertable.Peer{{Key: own}, probe}); err != nil {
		t.Fatal(err)
	}
	stored, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if holds(stored, own) {
		t.Fatal("the kernel-like fake held its own key; this gate would not exercise SEC-012")
	}
	if len(stored) != 1 || stored[0].AllowedIPs[0].String() != "10.9.0.0/24" {
		t.Fatal("the kernel-like fake did not mask its routes; this gate would not exercise SEC-019")
	}
	if err := fake.Replace(nil); err != nil {
		t.Fatal(err)
	}
	before := fake.Writes()
	a := newAgent(t, reconcile.Owner, servedLog(t), fake, &recorder{})
	a.cfg.Provider = endpoint.Static{Peers: map[string]endpoint.Hints{
		"nas":    {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.8.0.1/32")}},
		"pi-cam": {AllowedIPs: []netip.Prefix{unmasked}},
	}}
	a.cfg.Mono = func() time.Duration { return 0 }
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	installed := fake.Writes()
	if installed != before+1 {
		t.Fatalf("the first cycle made %d writes, want one", installed-before)
	}
	for i := 0; i < 50; i++ {
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
	}
	if fake.Writes() != installed {
		t.Errorf("%d further writes on an unchanged kernel-like interface", fake.Writes()-installed)
	}
}

// Gate line: "Observe mode: 24 h soak, zero writes to the interface". One
// cycle proving that is weak; the soak's real subject is a busy interface, so
// this is many cycles with somebody else churning the table throughout.
func TestObserveWritesNothingEvenWhileTheTableChurns(t *testing.T) {
	dir, _, _ := writableLog(t)
	rec := &recorder{}
	fake := peertable.NewFake(provenKeys(t)...)
	a := newAgent(t, reconcile.Observe, dir, fake, rec)

	for i := 0; i < 25; i++ {
		var intruder peertable.Key
		intruder[0] = byte(i)
		fake.Inject(peertable.Peer{Key: intruder})
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
	}
	if fake.Writes() != 0 {
		t.Fatalf("observe wrote %d times: %+v", fake.Writes(), fake.Calls)
	}
	if rec.kinds()[reconcile.UnprovenPeer] < 25 {
		t.Errorf("observe should have alarmed on every intruder: %v", rec.kinds())
	}
}

// Gate line: "rogue key ... is evicted" — the p99 is the lab's, but that the
// eviction happens on the *next* cycle rather than some later one is what
// makes the window equal to T_poll at all.
func TestAnIntruderIsGoneAfterExactlyOneCycle(t *testing.T) {
	dir, _, _ := writableLog(t)
	rec := &recorder{}
	fake := peertable.NewFake(provenKeys(t)...)
	a := newAgent(t, reconcile.Watchdog, dir, fake, rec)

	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	fake.Inject(rogue(t))
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	peers, _ := fake.Peers()
	if holds(peers, rogue(t).Key) {
		t.Fatal("an intruder survived the first cycle after it appeared")
	}
}

// A node's freshness state has to follow witness time as the node keeps
// running: the same checkpoint, adopted once and never replaced, goes from
// fresh to degraded to hard-stale as elapsed time passes -- and the transition
// is driven by a monotonic reading, so moving the machine's wall clock changes
// nothing.
func TestAViewAgesFromWitnessTimeNotTheWallClock(t *testing.T) {
	dir, _, _ := writableLog(t)

	var elapsed time.Duration
	// A wall clock that lurches an hour forward between cycles. Nothing below
	// may notice.
	wall := time.Unix(1_760_000_000, 0)
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(dir), Device: peertable.NewFake(),
		Mode: reconcile.Observe, RunDir: t.TempDir(), Emit: rec.emit,
		Now:  func() time.Time { wall = wall.Add(time.Hour); return wall },
		Mono: func() time.Duration { return elapsed },
		Hard: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		mono time.Duration
		want string
	}{
		{0, freshness.Fresh},
		{14 * time.Minute, freshness.Fresh},
		{16 * time.Minute, freshness.Degraded},
		{90 * time.Minute, freshness.HardStale},
	} {
		elapsed = tc.mono
		if err := a.Once(); err != nil {
			t.Fatalf("cycle at %v: %v", tc.mono, err)
		}
		set, err := proven.Read(filepath.Join(a.cfg.RunDir, proven.FileName))
		if err != nil {
			t.Fatal(err)
		}
		if set.Freshness != tc.want {
			t.Errorf("after %v: freshness = %q, want %q", tc.mono, set.Freshness, tc.want)
		}
	}
}

// GOSSIP.md part 8, T5: a node whose wall clock is two hours out must raise
// CLOCK_SKEW, must **not** go degraded, and must leave the proven set alone.
// The wall clock is allowed to produce exactly one finding, and that finding
// changes nothing about what this node enforces (A11).
func TestASkewedWallClockAlarmsAndChangesNothing(t *testing.T) {
	dir, _, _ := writableLog(t)
	rec := &recorder{}
	fake := peertable.NewFake()

	// Witness time is the fixture's cosigning instant; this machine believes
	// it is two hours later.
	skewed := time.Unix(fixtureCosignedAt, 0).Add(2 * time.Hour)
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(dir), Device: fake,
		Mode: reconcile.Owner, RunDir: t.TempDir(), Emit: rec.emit,
		Now:  func() time.Time { return skewed },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}

	if rec.kinds()[ClockSkew] != 1 {
		t.Errorf("events = %v, want one %s", rec.kinds(), ClockSkew)
	}
	set, err := proven.Read(filepath.Join(a.cfg.RunDir, proven.FileName))
	if err != nil {
		t.Fatal(err)
	}
	// Not degraded: the log is perfectly current, this machine is not.
	if set.Freshness != freshness.Fresh {
		t.Errorf("freshness = %q, want %q: a wrong local clock must not age the view",
			set.Freshness, freshness.Fresh)
	}
	// And the peer table is exactly what the log proves.
	peers, err := fake.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != len(set.Devices) {
		t.Errorf("%d peers for %d proven devices: the clock changed enforcement",
			len(peers), len(set.Devices))
	}
}

// The converse, and the reason the naive formula is not enough: the log really
// is two hours stale and this node's clock is right. That is `degraded`, and
// it is not a clock problem -- reporting one would send an operator to fix the
// wrong machine.
func TestAStaleLogIsNotReportedAsClockSkew(t *testing.T) {
	dir, _, _ := writableLog(t)
	rec := &recorder{}

	// The node adopts at monotonic 0 and asks again two hours later, with a
	// wall clock that has advanced by exactly the same two hours.
	var elapsed time.Duration
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(dir), Device: peertable.NewFake(),
		Mode: reconcile.Observe, RunDir: t.TempDir(), Emit: rec.emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(elapsed) },
		Mono: func() time.Duration { return elapsed },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	elapsed = 2 * time.Hour
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}

	if got := rec.kinds()[ClockSkew]; got != 0 {
		t.Errorf("%d clock-skew alarms for a stale log; the operator would fix the "+
			"wrong machine", got)
	}
	set, err := proven.Read(filepath.Join(a.cfg.RunDir, proven.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if set.Freshness != freshness.Degraded {
		t.Errorf("freshness = %q, want %q", set.Freshness, freshness.Degraded)
	}
}

// D-020, the part that only matters to a node that keeps running: a rotation
// published in the log is followed, because the node learned the key by
// replaying a log it had already accepted.
//
// The agent is where this has to work. A one-shot `norn verify` holds only its
// trust file and is meant to refuse a key it has never seen; a node that has
// been watching the log has seen the rotation and must not stop at it.
func TestTheAgentFollowsALogKeyRotation(t *testing.T) {
	dir, store, _ := writableLog(t)
	doc := anchor(t)

	rec := &recorder{}
	a, err := New(Config{
		Anchor: doc, Fetcher: logclient.Dir(dir), Device: peertable.NewFake(),
		Mode: reconcile.Owner, Emit: rec.emit,
		Now: func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatalf("the first round did not verify: %v", err)
	}
	if len(a.last.State.LogKeys) == 0 {
		t.Fatal("the fixture publishes no log_key entry, so nothing here is tested")
	}

	// The log starts signing with the key its roots published.
	signed, err := store.SignedCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := note.Split(signed)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := note.Sign(body, doc.Origin, fixtureKey(t, "logkey2"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err = cosign.Append(fixtureWitnesses(t),
		cosign.At(time.Unix(fixtureCosignedAt, 0)))(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(rotated), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := a.Once(); err != nil {
		t.Errorf("the node stopped at a rotation it had already replayed: %v\n"+
			"A node that watched the roots publish a key must follow it, or every "+
			"rotation is an outage for exactly the nodes that were paying attention.", err)
	}
}

// D-020's other half: the witness policy supersedes inside the log.
//
// The fixture's roots raise the quorum from two of three to three of three at
// entry 49. A node holding only the trust file requires two; a node that has
// replayed the rotation requires three. A head cosigned by exactly two is
// therefore acceptable to the first and not to the second -- which is the
// whole point of being able to raise a quorum without re-provisioning anybody.
func TestTheAgentFollowsAPolicyRotation(t *testing.T) {
	dir, store, _ := writableLog(t)
	doc := anchor(t)

	rec := &recorder{}
	a, err := New(Config{
		Anchor: doc, Fetcher: logclient.Dir(dir), Device: peertable.NewFake(),
		Mode: reconcile.Owner, Emit: rec.emit,
		Now: func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatalf("the first round did not verify: %v", err)
	}
	if !strings.Contains(a.last.State.Policy, "group home 3") {
		t.Fatalf("the fixture's roots do not raise the quorum, so nothing here is "+
			"tested; state.policy is %q", a.last.State.Policy)
	}

	// The log grows and publishes a head two of the three witnesses cosigned:
	// enough for the trust file's policy, short of the one the roots
	// published. It must be a new head: the held one, read again with fewer
	// lines, keeps the policy it was accepted under (D-082 (1)).
	appendRevoke(t, store, "nas", uint64(a.last.Checkpoint.Size))
	signed, err := store.SignedCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := note.Split(signed)
	if err != nil {
		t.Fatal(err)
	}
	head, err := note.Sign(body, doc.Origin, fixtureKey(t, "logkey"))
	if err != nil {
		t.Fatal(err)
	}
	head, err = cosign.Append(fixtureWitnesses(t)[:2],
		cosign.At(time.Unix(fixtureCosignedAt, 0)))(head)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := a.Once(); err == nil {
		t.Error("a node that replayed the roots raising the quorum accepted a head " +
			"short of it; raising a quorum would then protect nobody who was already " +
			"watching")
	}
}
