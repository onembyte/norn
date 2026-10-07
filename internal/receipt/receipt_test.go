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
	if code, ok := CodeOf(err); !ok || code != Entry {
		t.Errorf("CodeOf(%v) = %q, %t; want %q", err, code, ok, Entry)
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
		code   Code
	}{
		{"signed by another key", signed(t, other, origin, origin, leaf, future),
			[]string{good}, origin, "trusts", LogSignature},
		{"no key to check against", signed(t, k, origin, origin, leaf, future),
			nil, origin, "no log key", LogSignature},
		{"for another log", signed(t, k, origin, "norn/elsewhere", leaf, future),
			[]string{good}, origin, "not", Origin},
		{"signed under another name", signed(t, k, "norn/elsewhere", origin, leaf, future),
			[]string{good}, origin, "trusts", LogSignature},
		{"already expired", signed(t, k, origin, origin, leaf, uint64(now.Unix())),
			[]string{good}, origin, "already passed", Expired},
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
			if code, ok := CodeOf(err); !ok || code != c.code {
				t.Errorf("CodeOf(%v) = %q, %t; want %q", err, code, ok, c.code)
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
	wantCodes := map[string]Code{
		"three lines":           ReceiptFormat,
		"wrong header":          ReceiptFormat,
		"leaf not base64":       LeafHash,
		"short leaf":            LeafHash,
		"deadline not a number": Deadline,
		"five lines":            ReceiptFormat,
	}
	for why, text := range bad {
		t.Run(why, func(t *testing.T) {
			raw, err := note.Sign(text, origin, k)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Check(raw, []string{vkey(t, k, origin)}, origin, leaf, now); err == nil {
				t.Errorf("accepted a receipt with %s", why)
			} else if code, ok := CodeOf(err); !ok || code != wantCodes[why] {
				t.Errorf("CodeOf(%v) = %q, %t; want %q", err, code, ok, wantCodes[why])
			}
		})
	}
}

func TestMalformedNotePrecedesSignatureLookup(t *testing.T) {
	k := key(t)
	leaf := leafHash(t, "an entry")
	raw := signed(t, k, origin, origin, leaf, 1_760_000_060) + "\n"
	if _, err := Check(raw, nil, origin, leaf, time.Time{}); err == nil {
		t.Fatal("accepted an extra final newline")
	} else if code, ok := CodeOf(err); !ok || code != Note {
		t.Errorf("CodeOf(%v) = %q, %t; want %q", err, code, ok, Note)
	}
}

func TestReceiptCodesAreClosedAndOrdered(t *testing.T) {
	want := []Code{Note, LogSignature, ReceiptFormat, Origin, LeafHash, Deadline, Entry, Expired}
	got := All()
	if strings.Join(codeStrings(got), ",") != strings.Join(codeStrings(want), ",") {
		t.Fatalf("All() = %v, want %v", got, want)
	}
	got[0] = "unlisted"
	if !Known(Note) || Known("unlisted") {
		t.Fatal("receipt refusal vocabulary is not closed")
	}
}

func codeStrings(codes []Code) []string {
	out := make([]string, len(codes))
	for i, code := range codes {
		out[i] = string(code)
	}
	return out
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
	} else if code, ok := CodeOf(err); !ok || code != Deadline {
		t.Errorf("CodeOf(%v) = %q, %t; want %q", err, code, ok, Deadline)
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

func TestReceiptLeafHashRejectsNonzeroPadBits(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	bad, err := os.ReadFile(filepath.Join(root, "receipt-bad", "leaf-hash-nonzero-pad-bits.note"))
	if err != nil {
		t.Fatal(err)
	}
	honest, err := os.ReadFile(filepath.Join(root, "receipt.note"))
	if err != nil {
		t.Fatal(err)
	}
	keys := anchorLogKey(t, root)
	leaf, anchoredOrigin, deadline := receiptFacts(t, root)
	when := time.Unix(deadline-1, 0)
	if _, err := Check(string(honest), keys, anchoredOrigin, leaf, when); err != nil {
		t.Fatalf("the canonical receipt is invalid: %v", err)
	}
	badText, err := note.Verify(string(bad), keys)
	if err != nil {
		t.Fatalf("the altered receipt must have a valid log signature: %v", err)
	}
	honestText, err := note.Verify(string(honest), keys)
	if err != nil {
		t.Fatal(err)
	}
	badLines, honestLines := strings.Split(badText, "\n"), strings.Split(honestText, "\n")
	if len(badLines) != 5 || len(honestLines) != 5 || badLines[0] != honestLines[0] ||
		badLines[1] != honestLines[1] || badLines[3] != honestLines[3] || badLines[4] != honestLines[4] {
		t.Fatal("the vector changes more than the leaf-hash line")
	}
	if len(badLines[2]) != len(honestLines[2]) || badLines[2] == honestLines[2] {
		t.Fatal("the vector must change the base64 spelling at the same length")
	}
	for i := range badLines[2] {
		if badLines[2][i] != honestLines[2][i] && i != len(badLines[2])-2 {
			t.Fatal("the vector changes a character outside the final data character")
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(badLines[2])
	if err != nil || string(decoded) != string(leaf) {
		t.Fatalf("the alternate spelling does not decode to the same leaf hash: %v", err)
	}
	if _, err := Check(string(bad), keys, anchoredOrigin, leaf, when); err == nil {
		t.Fatal("accepted a correctly signed receipt with non-zero leaf-hash pad bits")
	} else if code, ok := CodeOf(err); !ok || code != LeafHash {
		t.Errorf("CodeOf(%v) = %q, %t; want %q", err, code, ok, LeafHash)
	}
}

func TestReceiptBadVectorsMatchTheirDeclaredCodes(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	var manifest struct {
		Cases []struct {
			Name    string `json:"name"`
			NowUnix *int64 `json:"now_unix"`
		} `json:"cases"`
		Codes map[string]Code `json:"codes"`
		Rules map[string]struct {
			Section string `json:"section"`
			Says    string `json:"says"`
		} `json:"rules"`
	}
	rawManifest, err := os.ReadFile(filepath.Join(root, "receipt-bad", "cases.json"))
	if err != nil {
		t.Fatalf("read receipt-bad/cases.json: %v", err)
	}
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		t.Fatalf("parse receipt-bad/cases.json: %v", err)
	}
	if len(manifest.Cases) == 0 || len(manifest.Cases) != len(manifest.Codes) || len(manifest.Cases) != len(manifest.Rules) {
		t.Fatalf("receipt-bad manifest has %d cases, %d codes, %d rules",
			len(manifest.Cases), len(manifest.Codes), len(manifest.Rules))
	}
	leaf, expectedOrigin, deadline := receiptFacts(t, root)
	keys := anchorLogKey(t, root)
	names := make(map[string]bool, len(manifest.Cases))
	for _, c := range manifest.Cases {
		if c.Name == "" || names[c.Name] {
			t.Errorf("empty or duplicate receipt-bad case name %q", c.Name)
			continue
		}
		names[c.Name] = true
		code, ok := manifest.Codes[c.Name]
		if !ok || !Known(code) {
			t.Errorf("%s declares unknown or absent receipt code %q", c.Name, code)
			continue
		}
		rule, ok := manifest.Rules[c.Name]
		if !ok || rule.Section != "7" || rule.Says == "" {
			t.Errorf("%s has no concrete §7 rule", c.Name)
		}
		vector, err := os.ReadFile(filepath.Join(root, "receipt-bad", c.Name))
		if err != nil {
			t.Errorf("read receipt-bad/%s: %v", c.Name, err)
			continue
		}
		now := deadline - 1
		if c.NowUnix != nil {
			now = *c.NowUnix
		}
		_, err = Check(string(vector), keys, expectedOrigin, leaf, time.Unix(now, 0))
		got, coded := CodeOf(err)
		if err == nil || !coded || got != code {
			t.Errorf("%s: Check code = %q, %t (error %v), want %q", c.Name, got, coded, err, code)
		}
	}
	for name := range manifest.Codes {
		if !names[name] {
			t.Errorf("receipt-bad code %s has no case", name)
		}
	}
	for name := range manifest.Rules {
		if !names[name] {
			t.Errorf("receipt-bad rule %s has no case", name)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "receipt-bad"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == "cases.json" {
			continue
		}
		if !names[entry.Name()] {
			t.Errorf("receipt-bad/%s is not in cases.json", entry.Name())
		}
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
