package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/trust"
)

// `receipt.note` and `receipts-bad/` are read here exactly as their manifest
// says: under trust.cbor's log key and origin, with no entry in hand and no
// clock -- the monitor's call, and the one where every refusal is a property
// of the file (SPEC §7, cold gate run 11, D4).

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func shippedAnchor(t *testing.T) *trust.Trust {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return anchor
}

type shippedMeta struct {
	Origin   string `json:"origin"`
	LeafHash string `json:"leaf_hash"`
	Deadline uint64 `json:"deadline"`
}

func readShipped(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func honestReceipt(t *testing.T) (signed string, meta shippedMeta) {
	t.Helper()
	if err := json.Unmarshal([]byte(readShipped(t, "receipt.json")), &meta); err != nil {
		t.Fatal(err)
	}
	return readShipped(t, "receipt.note"), meta
}

// The positive half: a reader that refuses the honest receipt refuses
// everything in `receipts-bad/` for free.
func TestTheShippedReceiptIsAccepted(t *testing.T) {
	anchor := shippedAnchor(t)
	signed, meta := honestReceipt(t)
	leaf, err := hex.DecodeString(meta.LeafHash)
	if err != nil {
		t.Fatal(err)
	}
	for _, bound := range [][]byte{nil, leaf} {
		got, err := Check(signed, []string{anchor.LogKey}, anchor.Origin, bound, time.Time{})
		if err != nil {
			t.Fatalf("receipt.note is refused (leaf bound: %v): %v", bound != nil, err)
		}
		if got.Origin != meta.Origin || string(got.LeafHash) != string(leaf) ||
			got.Deadline != meta.Deadline {
			t.Errorf("receipt.note reads as %+v, and receipt.json says %+v", got, meta)
		}
	}
}

// What each refusal must be about. A case refused for some other reason is
// refused by a rule it was not built to isolate, which is the defect every
// earlier negative directory had to be fixed for at least once.
var receiptRefusals = map[string]string{
	"two-log-signatures":    "does not verify",
	"extension-line":        "this one has 5",
	"wrong-version":         "first line is",
	"origin-with-a-suffix":  "it is for",
	"origin-in-upper-case":  "it is for",
	"origin-truncated":      "it is for",
	"leaf-hash-too-long":    "the leaf hash is 33 bytes",
	"deadline-leading-zero": "is not canonical decimal",
	// Cold gate run 11, the D4 review: the other half of each of the last
	// two rules, and the three other spellings of one leaf.
	"deadline-plus-sign":               "not a unix timestamp",
	"deadline-above-uint64":            "does not fit in 64 bits",
	"leaf-hash-too-short":              "the leaf hash is 31 bytes",
	"leaf-hash-unpadded":               "the leaf hash is not base64",
	"leaf-hash-non-canonical-pad-bits": "is not the encoding of the leaf hash",
	"leaf-hash-carriage-return":        "is not the encoding of the leaf hash",
}

func receiptCases(t *testing.T) []string {
	t.Helper()
	var doc struct {
		Cases []struct{ Name string } `json:"cases"`
	}
	if err := json.Unmarshal([]byte(readShipped(t, "receipts-bad/cases.json")), &doc); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range doc.Cases {
		names = append(names, c.Name)
	}
	// The manifest and the directory agree, both ways.
	files, err := filepath.Glob(filepath.Join(vectorRoot(), "receipts-bad", "*.note"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []string
	for _, f := range files {
		onDisk = append(onDisk, strings.TrimSuffix(filepath.Base(f), ".note"))
	}
	listed := append([]string(nil), names...)
	sort.Strings(listed)
	sort.Strings(onDisk)
	if strings.Join(listed, ",") != strings.Join(onDisk, ",") {
		t.Fatalf("receipts-bad/cases.json lists %v and the directory holds %v", listed, onDisk)
	}
	return names
}

func textLines(text string) []string {
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// Shape before verdict. Each case is the honest receipt with one line changed
// or added and a signature that verifies, so the signature cannot refuse it
// first -- except `two-log-signatures`, whose text is the honest one and whose
// second line is a forged copy of the first. Only then is it refused, and for
// the rule it is named after.
func TestEveryReceiptNegativeIsRefusedForItsOwnRule(t *testing.T) {
	anchor := shippedAnchor(t)
	logKey, err := note.ParseVerifierKey(anchor.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	honestSigned, meta := honestReceipt(t)
	honestText, honestSigs, err := note.Split(honestSigned)
	if err != nil {
		t.Fatal(err)
	}
	honest := textLines(honestText)
	leaf, err := hex.DecodeString(meta.LeafHash)
	if err != nil {
		t.Fatal(err)
	}

	names := receiptCases(t)
	if len(names) != len(receiptRefusals) {
		t.Errorf("receipts-bad has %d cases and this test knows %d: a new case needs a "+
			"shape check and a refusal here", len(names), len(receiptRefusals))
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			says, known := receiptRefusals[name]
			if !known {
				t.Fatalf("no refusal is recorded for %s", name)
			}
			signed := readShipped(t, filepath.Join("receipts-bad", name+".note"))
			text, sigs, err := note.Split(signed)
			if err != nil {
				t.Fatalf("%s is not a well-framed note, so §7's framing refuses it first: %v",
					name, err)
			}
			lines := textLines(text)

			if name == "two-log-signatures" {
				if text != honestText {
					t.Fatal("the text is not receipt.note's")
				}
				if len(sigs) != 2 || string(sigs[0].Sig) != string(honestSigs[0].Sig) {
					t.Fatal("want receipt.note's own line followed by one more")
				}
				for i, s := range sigs {
					if s.Name != logKey.Name || string(s.KeyID) != string(logKey.ID()) {
						t.Fatalf("line %d is not under the log's name and key id", i)
					}
				}
				if ed25519.Verify(logKey.Public, []byte(text), sigs[1].Sig) {
					t.Fatal("the second line verifies, so nothing about it is forged")
				}
			} else {
				if _, err := note.Verify(signed, []string{anchor.LogKey}); err != nil {
					t.Fatalf("the log key's signature does not verify, so it refuses "+
						"this first: %v", err)
				}
				if len(sigs) != 1 {
					t.Fatalf("%d signature lines, want the log's one", len(sigs))
				}
				changed := 0
				for i := 0; i < len(honest) && i < len(lines); i++ {
					if lines[i] != honest[i] {
						changed++
					}
				}
				added := len(lines) - len(honest)
				if added < 0 || changed+added != 1 {
					t.Fatalf("differs from receipt.note in %d lines and adds %d; a "+
						"negative differs in exactly one", changed, added)
				}
			}

			switch name {
			case "extension-line":
				if len(lines) != 5 {
					t.Fatalf("%d lines, want the honest four and one more", len(lines))
				}
			case "wrong-version":
				if lines[0] == note.ReceiptHeader || !strings.HasPrefix(lines[0], "norn/receipt/") {
					t.Fatalf("first line %q is not another version of the header", lines[0])
				}
			case "origin-with-a-suffix":
				if !strings.HasPrefix(lines[1], anchor.Origin) || lines[1] == anchor.Origin {
					t.Fatalf("%q does not extend %q", lines[1], anchor.Origin)
				}
			case "origin-truncated":
				if !strings.HasPrefix(anchor.Origin, lines[1]) || lines[1] == anchor.Origin {
					t.Fatalf("%q is not a truncation of %q", lines[1], anchor.Origin)
				}
			case "origin-in-upper-case":
				if !strings.EqualFold(lines[1], anchor.Origin) || lines[1] == anchor.Origin {
					t.Fatalf("%q is not %q in another case", lines[1], anchor.Origin)
				}
			case "leaf-hash-too-long":
				raw, err := base64.StdEncoding.DecodeString(lines[2])
				if err != nil || len(raw) != 33 || string(raw[:32]) != string(leaf) {
					t.Fatalf("%q is not 33 bytes led by the honest leaf hash", lines[2])
				}
			case "deadline-leading-zero":
				n, err := strconv.ParseUint(lines[3], 10, 64)
				if err != nil || n != meta.Deadline || lines[3] == strconv.FormatUint(n, 10) {
					t.Fatalf("%q is not receipt.json's deadline with a leading zero", lines[3])
				}
			case "deadline-plus-sign":
				// The lax reading, run for real: a signed parse gives the
				// honest deadline, and nothing about it leads with a zero.
				n, err := strconv.ParseInt(lines[3], 10, 64)
				if err != nil || uint64(n) != meta.Deadline || lines[3][0] != '+' {
					t.Fatalf("%q is not receipt.json's deadline with a plus sign", lines[3])
				}
			case "deadline-above-uint64":
				_, err := strconv.ParseUint(lines[3], 10, 64)
				if !errors.Is(err, strconv.ErrRange) || strings.Trim(lines[3], "0123456789") != "" ||
					lines[3][0] == '0' {
					t.Fatalf("%q is not a canonical decimal above 2^64-1", lines[3])
				}
			case "leaf-hash-too-short":
				raw, err := base64.StdEncoding.DecodeString(lines[2])
				if err != nil || len(raw) != 31 || string(raw) != string(leaf[:31]) {
					t.Fatalf("%q is not the honest leaf hash less its last byte", lines[2])
				}
			case "leaf-hash-unpadded":
				raw, err := base64.RawStdEncoding.DecodeString(lines[2])
				if err != nil || string(raw) != string(leaf) || strings.HasSuffix(lines[2], "=") {
					t.Fatalf("%q is not the honest leaf line without its padding", lines[2])
				}
			case "leaf-hash-non-canonical-pad-bits":
				// The lenient decoder reads the honest leaf; the strict one
				// refuses the line; and the line is the honest one's length.
				raw, err := base64.StdEncoding.DecodeString(lines[2])
				if err != nil || string(raw) != string(leaf) || len(lines[2]) != len(honest[2]) {
					t.Fatalf("%q does not read as the honest leaf under a lenient decoder", lines[2])
				}
				if _, err := base64.StdEncoding.Strict().DecodeString(lines[2]); err == nil {
					t.Fatalf("%q has canonical padding bits, so it is the honest line", lines[2])
				}
			case "leaf-hash-carriage-return":
				if !strings.Contains(lines[2], "\r") ||
					strings.ReplaceAll(lines[2], "\r", "") != honest[2] {
					t.Fatalf("%q is not the honest leaf line with a CR inside it", lines[2])
				}
			}

			_, err = Check(signed, []string{anchor.LogKey}, anchor.Origin, nil, time.Time{})
			if err == nil {
				t.Fatalf("accepted; SPEC §7 says whoever holds this receipt MUST refuse it")
			}
			if !strings.Contains(err.Error(), says) {
				t.Errorf("refused for %v, and the case is about %q", err, says)
			}
		})
	}
}
