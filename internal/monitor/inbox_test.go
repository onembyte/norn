package monitor

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
)

// SPEC §7, and it is worth quoting because every decision here follows from
// it: "A receipt whose leaf is absent from every checkpoint **cosigned after
// `deadline`** is non-repudiable proof of log misbehaviour."
//
// Cosigned after. Not "later than the monitor's clock says" -- the comparison
// is against **witness time**, so the finding does not depend on the accuser's
// clock being right, which is exactly what makes it non-repudiable rather than
// an accusation.

func fixtureLogKey(t *testing.T) ed25519.PrivateKey {
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
	seed, err := hex.DecodeString(keys.Ed25519["logkey"].Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("no log key seed")
	}
	return ed25519.NewKeyFromSeed(seed)
}

// aReceipt is what the log hands back on submission: this leaf, by this
// deadline, signed by the log.
func aReceipt(t *testing.T, leaf []byte, deadline int64) string {
	t.Helper()
	doc := anchorOf(t)
	text := note.ReceiptHeader + "\n" + doc.Origin + "\n" +
		base64.StdEncoding.EncodeToString(leaf) + "\n" +
		formatUint(deadline) + "\n"
	signed, err := note.Sign(text, doc.Origin, fixtureLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func formatUint(v int64) string { return strings.TrimSpace(itoa(v)) }

// verifiedLog is the fixture's log, read as the monitor reads it.
func verifiedLog(t *testing.T) *logclient.Result {
	t.Helper()
	result, err := logclient.Verify(logclient.Dir(filepath.Join(vectors(), "served")),
		New(anchorOf(t), Default()).logAnchor())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// An entry that was included is not news, and the receipt is done with.
func TestAnIncludedReceiptIsResolved(t *testing.T) {
	result := verifiedLog(t)
	leaf := tlog.LeafHash(result.Served[10])

	inbox := NewInbox()
	if err := inbox.Add(aReceipt(t, leaf[:], fixtureCosigned-60), anchorOf(t), nil); err != nil {
		t.Fatal(err)
	}

	alerts := inbox.Check(result, Default())
	for _, a := range alerts {
		if a.Level == Critical {
			t.Errorf("an included entry raised %q", a.Message)
		}
	}
	if inbox.Pending() != 0 {
		t.Errorf("%d receipts still pending; an included one is finished with",
			inbox.Pending())
	}
}

// The finding this exists for: the deadline has passed in **witness time** and
// the leaf is in no checkpoint.
func TestAMissedDeadlineIsNonRepudiable(t *testing.T) {
	result := verifiedLog(t)
	// A leaf the log never carried.
	var absent [32]byte
	copy(absent[:], "this entry was never included...")

	inbox := NewInbox()
	// The deadline is before the witnesses cosigned the head the monitor holds.
	if err := inbox.Add(aReceipt(t, absent[:], fixtureCosigned-3600), anchorOf(t), nil); err != nil {
		t.Fatal(err)
	}

	alerts := inbox.Check(result, Default())
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want one", alerts)
	}
	if alerts[0].Level != Critical {
		t.Errorf("level = %s, want critical", alerts[0].Level)
	}
	for _, want := range []string{"promised", "cosigned"} {
		if !strings.Contains(alerts[0].Message, want) {
			t.Errorf("the alert should say what was promised and what witnesses "+
				"vouched for (%q missing): %q", want, alerts[0].Message)
		}
	}
	// It stays pending: the proof does not stop being true, and an operator
	// who was asleep still needs to find it in the morning.
	if inbox.Pending() != 1 {
		t.Error("a proven misbehaviour was dropped after being reported once")
	}
}

// A deadline the witnesses have not reached yet is not a missed deadline. The
// monitor's own clock is deliberately not consulted: a monitor running fast
// would otherwise accuse an honest log.
func TestADeadlineWitnessTimeHasNotReachedIsSilent(t *testing.T) {
	result := verifiedLog(t)
	var absent [32]byte
	copy(absent[:], "not yet due......................")

	inbox := NewInbox()
	if err := inbox.Add(aReceipt(t, absent[:], fixtureCosigned+3600), anchorOf(t), nil); err != nil {
		t.Fatal(err)
	}

	if alerts := inbox.Check(result, Default()); len(alerts) != 0 {
		t.Errorf("alerts = %+v, want none: the witnesses have not reached the "+
			"deadline, so the log has not missed it", alerts)
	}
}

// With no cosignature there is no witness time, so no deadline can be said to
// have passed. A monitor that fell back to its own clock here would turn every
// witness outage into an accusation against the log.
func TestWithoutWitnessTimeNoDeadlineHasPassed(t *testing.T) {
	result := verifiedLog(t)
	result.QuorumTime = nil
	var absent [32]byte
	copy(absent[:], "the witnesses are all offline...")

	inbox := NewInbox()
	if err := inbox.Add(aReceipt(t, absent[:], fixtureCosigned-3600), anchorOf(t), nil); err != nil {
		t.Fatal(err)
	}

	if alerts := inbox.Check(result, Default()); len(alerts) != 0 {
		t.Errorf("alerts = %+v, want none: with no witness time nothing can be "+
			"said to be late", alerts)
	}
}

// A receipt is only evidence if the log signed it. Anybody can forward one to
// the monitor, so anybody could forward a forgery.
func TestAForgedReceiptIsRefusedAtTheDoor(t *testing.T) {
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	doc := anchorOf(t)
	text := note.ReceiptHeader + "\n" + doc.Origin + "\nAAAA\n1\n"
	forged, err := note.Sign(text, doc.Origin, other)
	if err != nil {
		t.Fatal(err)
	}

	inbox := NewInbox()
	if err := inbox.Add(forged, doc, nil); err == nil {
		t.Fatal("a receipt this network's log never signed was accepted as evidence")
	}
	if inbox.Pending() != 0 {
		t.Error("a refused receipt was kept")
	}
}

// A receipt for another network is not this network's business.
func TestAReceiptForAnotherOriginIsRefused(t *testing.T) {
	doc := anchorOf(t)
	text := note.ReceiptHeader + "\nnorn/somebody-else\nAAAA\n1\n"
	signed, err := note.Sign(text, doc.Origin, fixtureLogKey(t))
	if err != nil {
		t.Fatal(err)
	}

	if err := NewInbox().Add(signed, doc, nil); err == nil {
		t.Fatal("a receipt for another network was accepted")
	}
}

// itoa avoids pulling strconv into the test's import list for one call.
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}

// §7, D-074 (a): a receipt verifies under the log keys the monitor trusts --
// the trust file's, plus those a state it has verified published. The shipped
// receipt signed by logkey2 (receipt-bad/untrusted-log-key.note, refused by a
// reader holding only trust.cbor) is admitted by a monitor that has learned
// the key, and still refused by one that has not.
func TestAReceiptUnderAKeyTheLogPublishedIsAdmitted(t *testing.T) {
	doc := anchorOf(t)
	raw, err := os.ReadFile(filepath.Join(vectors(), "receipt-bad", "untrusted-log-key.note"))
	if err != nil {
		t.Fatal(err)
	}
	signed := string(raw)
	if err := NewInbox().Add(signed, doc, nil); err == nil {
		t.Fatal("a monitor that knows only trust.cbor admitted a receipt under another key")
	}
	learned := logclient.KeysFrom(doc.Origin, verifiedLog(t).State)
	if len(learned) == 0 {
		t.Fatal("the fixture's log published no key; the test shows nothing")
	}
	if err := NewInbox().Add(signed, doc, learned); err != nil {
		t.Errorf("a monitor that learned the published keys refused the receipt: %v", err)
	}
}
