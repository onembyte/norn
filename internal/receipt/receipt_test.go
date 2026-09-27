package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/trust"
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

// --- Cold-model gate run 11, defect D4 ----------------------------------
//
// §6 is emphatic that the checkpoint's size line is canonical decimal — "`0124`
// and `124` are the same number and two spellings of one head" — and §7 showed
// the receipt's deadline as a bare `<uint>` with no such rule and no vector, so
// `ReceiptDeadlineLax` passed all 622 checks.
//
// It matters less than for a checkpoint, since a receipt is not gossiped and
// nothing is keyed on its bytes. But §7 sells a receipt as "non-repudiable
// proof of log misbehaviour", which means two parties will one day compare two
// copies of one, and a number with two spellings is a comparison with two
// answers. The asymmetry had no reason behind it.

func TestTheDeadlineIsCanonicalDecimal(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	padded, err := os.ReadFile(filepath.Join(root, "receipt-bad", "leading-zero.note"))
	if err != nil {
		t.Fatalf("no receipt negative for the deadline's spelling: %v", err)
	}
	honest, err := os.ReadFile(filepath.Join(root, "receipt.note"))
	if err != nil {
		t.Fatal(err)
	}
	keys := anchorLogKey(t, root)
	leaf, origin, deadline := receiptFacts(t, root)

	// The control parses, so the vector differs from it in one thing only.
	if _, err := Check(string(honest), keys, origin, leaf, time.Unix(deadline-1, 0)); err != nil {
		t.Fatalf("the shipped receipt does not verify: %v", err)
	}
	if _, err := Check(string(padded), keys, origin, leaf, time.Unix(deadline-1, 0)); err == nil {
		t.Error("a deadline written with a leading zero was accepted; §7 says " +
			"canonical decimal, as §6's size line is")
	}

	// ...and the only thing wrong with it is that zero. The note is re-signed
	// over its own text, so its signature is impeccable -- verify it under the
	// log key -- and stripping the zero from the TEXT gives the honest text
	// back exactly. The signature lines differ of necessity and are not part
	// of the comparison.
	paddedText, err := note.Verify(string(padded), keys)
	if err != nil {
		t.Fatalf("the vector's own signature does not verify (%v), so it would be "+
			"refused for that rather than for the deadline's spelling", err)
	}
	honestText, err := note.Verify(string(honest), keys)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Replace(paddedText, "\n0", "\n", 1) != honestText {
		t.Errorf("the vector's text is not the honest text with one leading zero "+
			"added:\n got %q\nwant %q", paddedText, honestText)
	}
}

func receiptFacts(t *testing.T, root string) (leaf []byte, origin string, deadline int64) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Origin   string `json:"origin"`
		LeafHash string `json:"leaf_hash"`
		Deadline int64  `json:"deadline"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	leaf, err = hex.DecodeString(doc.LeafHash)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, doc.Origin, doc.Deadline
}

// anchorLogKey is the verifier key the shipped trust file names for the log.
func anchorLogKey(t *testing.T, root string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return []string{doc.LogKey}
}
