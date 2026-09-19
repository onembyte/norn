package agent

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlogstore"
)

// These tests are the software halves of `PLAN.md`'s Phase 3 gate. The gate
// itself is measurements -- a p99 over a thousand runs, two 24-hour soaks --
// and those belong to the lab. What does not belong to the lab is whether the
// behaviour being measured happens at all.

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
	store, err := tlogstore.Open(dir, doc.Origin, fixtureKey(t, "logkey"))
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

// appendRevoke writes a real `revoke` entry, signed by the two signers the
// fixture leaves active.
func appendRevoke(t *testing.T, store *tlogstore.Store, deviceID string, after uint64) {
	t.Helper()
	doc := anchor(t)
	env := &entry.Envelope{
		V: entry.Version, T: "revoke", Net: doc.Net, TS: 1_760_500_000, After: &after,
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

// keyOfDevice reads a device's WireGuard key out of the verified log.
func keyOfDevice(t *testing.T, id string) peertable.Key {
	t.Helper()
	doc := anchor(t)
	result, err := logclient.Verify(logclient.Dir(filepath.Join(vectors(), "served")),
		logclient.Anchor{Anchor: replay.Anchor{Net: doc.Net, GenesisHash: doc.GenesisHash}, LogKeys: []string{doc.LogKey}})
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
