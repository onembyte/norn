package receipt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
)

// Cold gate run 13, D4. §7 says a reader MUST check in its order and the
// first failed step decides, and §12.1 said the receipt order was vectored --
// but no `receipt-bad/` file failed two adjacent steps, so a reader that
// swapped any pair passed. One case per pair; each must be refused for the
// earlier step (the data-driven test checks the code) and must really carry
// the later step's fault, or it pins nothing. That second half is what this
// test checks.
func TestEveryAdjacentPairOfTheReceiptOrderIsVectored(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	var manifest struct {
		Cases []struct {
			Name    string `json:"name"`
			NowUnix *int64 `json:"now_unix"`
		} `json:"cases"`
		Codes map[string]Code `json:"codes"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "receipt-bad", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	now := map[string]*int64{}
	for _, c := range manifest.Cases {
		now[c.Name] = c.NowUnix
	}
	keys := anchorLogKey(t, root)
	leaf, anchored, _ := receiptFacts(t, root)

	// lines is the signed text, read without verifying it: the first pair's
	// earlier fault is a signature nothing trusted made.
	lines := func(t *testing.T, signed string) []string {
		t.Helper()
		text, _, err := note.Split(signed)
		if err != nil {
			t.Fatalf("the note does not split, so step 1 decides it: %v", err)
		}
		out := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		if len(out) != 4 {
			t.Fatalf("%d signed-text lines; step 3 would refuse every one of them", len(out))
		}
		return out
	}
	canonicalLeaf := func(line string) bool {
		decoded, err := base64.StdEncoding.Strict().DecodeString(line)
		return err == nil && len(decoded) == 32 && base64.StdEncoding.EncodeToString(decoded) == line
	}
	canonicalDeadline := func(line string) bool {
		n, err := strconv.ParseUint(line, 10, 64)
		return err == nil && strconv.FormatUint(n, 10) == line
	}

	for _, c := range []struct {
		name  string
		code  Code
		later string
		fault func(t *testing.T, name, signed string) bool
	}{
		{"order-log-signature-before-receipt.note", LogSignature, "a wrong header",
			func(t *testing.T, _, signed string) bool { return lines(t, signed)[0] != "norn/receipt/v1" }},
		{"order-receipt-before-origin.note", ReceiptFormat, "a foreign origin",
			func(t *testing.T, _, signed string) bool { return lines(t, signed)[1] != anchored }},
		{"order-origin-before-leaf-hash.note", Origin, "a non-canonical leaf hash",
			func(t *testing.T, _, signed string) bool { return !canonicalLeaf(lines(t, signed)[2]) }},
		{"order-leaf-hash-before-deadline.note", LeafHash, "a non-canonical deadline",
			func(t *testing.T, _, signed string) bool { return !canonicalDeadline(lines(t, signed)[3]) }},
		{"order-deadline-before-entry.note", Deadline, "another entry's leaf hash",
			func(t *testing.T, _, signed string) bool {
				decoded, err := base64.StdEncoding.DecodeString(lines(t, signed)[2])
				return err == nil && !bytes.Equal(decoded, leaf)
			}},
		{"order-entry-before-expired.note", Entry, "a checking time at its deadline",
			func(t *testing.T, name, signed string) bool {
				deadline, err := strconv.ParseInt(lines(t, signed)[3], 10, 64)
				return err == nil && now[name] != nil && *now[name] != 0 && *now[name] >= deadline
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got, ok := manifest.Codes[c.name]; !ok || got != c.code {
				t.Fatalf("receipt-bad/%s declares %q (present %t), want %q", c.name, got, ok, c.code)
			}
			signed, err := os.ReadFile(filepath.Join(root, "receipt-bad", c.name))
			if err != nil {
				t.Fatal(err)
			}
			if !c.fault(t, c.name, string(signed)) {
				t.Errorf("it does not also carry %s, so a swapped order answers the same", c.later)
			}
			if c.code != LogSignature {
				if _, err := note.Verify(string(signed), keys); err != nil {
					t.Errorf("not signed by the anchored log key (%v): step 2 would decide it", err)
				}
			}
		})
	}
}
