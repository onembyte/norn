package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
)

const origin = "norn/receipt-test"

func key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/receipt-test/log"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func vkey(t *testing.T, k ed25519.PrivateKey, name string) string {
	t.Helper()
	return note.VerifierKey(name, k.Public().(ed25519.PublicKey))
}

func leafHash(t *testing.T, of string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(of))
	return sum[:]
}

func signed(t *testing.T, k ed25519.PrivateKey, name, org string, leaf []byte, deadline uint64) string {
	t.Helper()
	text, err := note.ReceiptText(org, leaf, deadline)
	if err != nil {
		t.Fatal(err)
	}
	out, err := note.Sign(text, name, k)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAGoodReceipt(t *testing.T) {
	k := key(t)
	leaf := leafHash(t, "an entry")
	now := time.Unix(1_760_000_000, 0)
	raw := signed(t, k, origin, origin, leaf, uint64(now.Unix())+60)

	got, err := Check(raw, []string{vkey(t, k, origin)}, origin, leaf, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != origin || string(got.LeafHash) != string(leaf) {
		t.Errorf("parsed wrongly: %+v", got)
	}
	if got.Deadline != uint64(now.Unix())+60 {
		t.Errorf("deadline = %d", got.Deadline)
	}
	if got.Signed != raw {
		t.Error("the receipt must keep the note it came from; that note is the evidence")
	}
	if !got.DeadlineTime().After(now) {
		t.Error("the deadline should be in the future")
	}
}

// The binding that makes a receipt evidence rather than a souvenir.
func TestAReceiptForAnotherEntryIsRefused(t *testing.T) {
	k := key(t)
	now := time.Unix(1_760_000_000, 0)
	raw := signed(t, k, origin, origin, leafHash(t, "some other entry"), uint64(now.Unix())+60)

	_, err := Check(raw, []string{vkey(t, k, origin)}, origin, leafHash(t, "mine"), now)
	if err == nil {
		t.Fatal("accepted a receipt about a different leaf")
	}
	if !strings.Contains(err.Error(), "different entry") {
		t.Errorf("the error should say what is wrong: %v", err)
	}
}

func TestRejections(t *testing.T) {
	k := key(t)
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	leaf := leafHash(t, "an entry")
	now := time.Unix(1_760_000_000, 0)
	future := uint64(now.Unix()) + 60
	good := vkey(t, k, origin)

	cases := []struct {
		why    string
		signed string
		keys   []string
		origin string
		says   string
	}{
		{"signed by another key", signed(t, other, origin, origin, leaf, future),
			[]string{good}, origin, "trusts"},
		{"no key to check against", signed(t, k, origin, origin, leaf, future),
			nil, origin, "no log key"},
		{"for another log", signed(t, k, origin, "norn/elsewhere", leaf, future),
			[]string{good}, origin, "not"},
		{"signed under another name", signed(t, k, "norn/elsewhere", origin, leaf, future),
			[]string{good}, origin, "trusts"},
		{"already expired", signed(t, k, origin, origin, leaf, uint64(now.Unix())),
			[]string{good}, origin, "already passed"},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			_, err := Check(c.signed, c.keys, c.origin, leaf, now)
			if err == nil {
				t.Fatalf("accepted a receipt that is %s", c.why)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("error = %v, want something about %q", err, c.says)
			}
		})
	}
}

func TestMalformedText(t *testing.T) {
	k := key(t)
	now := time.Unix(1_760_000_000, 0)
	leaf := leafHash(t, "an entry")

	bad := map[string]string{
		"three lines":           note.ReceiptHeader + "\n" + origin + "\nx\n",
		"wrong header":          "norn/receipt/v2\n" + origin + "\n" + base64.StdEncoding.EncodeToString(leaf) + "\n1\n",
		"leaf not base64":       note.ReceiptHeader + "\n" + origin + "\n!!!!\n1\n",
		"short leaf":            note.ReceiptHeader + "\n" + origin + "\n" + base64.StdEncoding.EncodeToString(leaf[:16]) + "\n1\n",
		"deadline not a number": note.ReceiptHeader + "\n" + origin + "\n" + base64.StdEncoding.EncodeToString(leaf) + "\nsoon\n",
		"five lines":            note.ReceiptHeader + "\n" + origin + "\n" + base64.StdEncoding.EncodeToString(leaf) + "\n1\nextra\n",
	}
	for why, text := range bad {
		t.Run(why, func(t *testing.T) {
			raw, err := note.Sign(text, origin, k)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Check(raw, []string{vkey(t, k, origin)}, origin, leaf, now); err == nil {
				t.Errorf("accepted a receipt with %s", why)
			}
		})
	}
}

func TestErrExpiredIsDistinguishable(t *testing.T) {
	if !errors.Is(ErrExpired, ErrExpired) {
		t.Fatal("the sentinel must be usable with errors.Is")
	}
}

// `now.Unix()` is negative for any time before 1970, and the zero `time.Time`
// is year 1. Casting that to uint64 wraps it to something enormous, which made
// **every** receipt look expired -- silently, and in the one direction that
// turns a valid promise into a refusal.
//
// The zero time now means what its only caller needs it to mean: do not judge
// the deadline at all. That is the right answer for anybody holding a receipt
// without a clock they trust -- the monitor judges deadlines against witness
// time (§7), not against its own.
func TestAZeroClockDoesNotJudgeTheDeadline(t *testing.T) {
	k := key(t)
	leaf := leafHash(t, "an entry")
	raw := signed(t, k, origin, origin, leaf, 1_760_000_000)
	keys := []string{vkey(t, k, origin)}

	if _, err := Check(raw, keys, origin, leaf, time.Time{}); err != nil {
		t.Errorf("a zero clock refused a valid receipt: %v", err)
	}
	// And a caller that does supply a clock still gets the check.
	if _, err := Check(raw, keys, origin, leaf, time.Unix(1_760_000_001, 0)); err == nil {
		t.Error("a passed deadline was accepted when a real clock was given")
	}
}

// Any pre-epoch clock would have done the same damage.
func TestAPreEpochClockDoesNotWrap(t *testing.T) {
	k := key(t)
	leaf := leafHash(t, "an entry")
	raw := signed(t, k, origin, origin, leaf, 1_760_000_000)

	if _, err := Check(raw, []string{vkey(t, k, origin)}, origin, leaf,
		time.Unix(-100, 0)); err != nil {
		t.Errorf("a clock set before 1970 refused a valid receipt: %v", err)
	}
}
