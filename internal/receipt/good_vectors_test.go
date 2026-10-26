package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/trust"
)

// A positive at the inclusive bound is what distinguishes the stated limit
// from one a second too strict. Bind it to the actual submitted genesis too.
func TestEveryPositiveReceiptBindsItsLeafAtTheInclusiveBound(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "receipt-good", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	// leaf_hash uses the manifest's customary snake-case spelling.
	var wire struct {
		Cases []struct {
			Name     string `json:"name"`
			File     string `json:"file"`
			LeafHash string `json:"leaf_hash"`
			Says     string `json:"says"`
			Now      int64  `json:"now"`
		} `json:"cases"`
		Codes map[string]string `json:"codes"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Cases) != 2 || wire.Cases[0].Name != "deadline-at-the-cap" || wire.Cases[1].Name != "deadline-zero-no-clock" {
		t.Fatal("missing deadline-at-the-cap or deadline-zero-no-clock positive")
	}
	anchorRaw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := trust.Parse(anchorRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := anchor.Validate(); err != nil {
		t.Fatal(err)
	}
	genesis, err := os.ReadFile(filepath.Join(root, "log", "0-genesis.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	leaf := sha256.Sum256(append([]byte{0}, genesis...))
	for _, c := range wire.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.File != c.Name+".note" || c.Now != 0 || wire.Codes[c.Name] != "accept" {
				t.Fatal("positive manifest must accept the named note with expiry skipped")
			}
			if c.LeafHash != hex.EncodeToString(leaf[:]) || string(leaf[:]) != string(anchor.GenesisHash) {
				t.Fatal("manifest must bind the genesis leaf")
			}
			signed, err := os.ReadFile(filepath.Join(root, "receipt-good", c.File))
			if err != nil {
				t.Fatal(err)
			}
			deadline := uint64(1<<63 - 1)
			deadlineText := "9223372036854775807"
			if c.Name == "deadline-zero-no-clock" {
				deadline = 0
				deadlineText = "0"
			}
			if !strings.Contains(string(signed), "\n"+deadlineText+"\n\n") {
				t.Fatal("wrong case-specific deadline")
			}
			// The ordinary receipt is the paired guard: the authenticated
			// body changes only its deadline, with the same log and leaf.
			ordinary, err := os.ReadFile(filepath.Join(root, "receipt.note"))
			if err != nil {
				t.Fatal(err)
			}
			cappedText, err := note.Verify(string(signed), []string{anchor.LogKey})
			if err != nil {
				t.Fatal(err)
			}
			ordinaryText, err := note.Verify(string(ordinary), []string{anchor.LogKey})
			if err != nil {
				t.Fatal(err)
			}
			cappedLines, ordinaryLines := strings.Split(cappedText, "\n"), strings.Split(ordinaryText, "\n")
			if len(cappedLines) != 5 || len(ordinaryLines) != 5 || strings.Join(cappedLines[:3], "\n") != strings.Join(ordinaryLines[:3], "\n") {
				t.Fatal("paired receipt differs outside the deadline")
			}
			if _, err := Check(string(ordinary), []string{anchor.LogKey}, anchor.Origin, leaf[:], time.Time{}); err != nil {
				t.Fatalf("deadline-only guard: %v", err)
			}
			t.Log("deadline-only guard accepted")
			got, err := Check(string(signed), []string{anchor.LogKey}, anchor.Origin, leaf[:], time.Time{})
			if err != nil {
				t.Fatalf("positive receipt: %v", err)
			}
			if got.Deadline != deadline || string(got.LeafHash) != string(leaf[:]) {
				t.Fatal("accepted receipt lost its deadline or leaf")
			}
			if c.Name == "deadline-zero-no-clock" {
				if _, err := Check(string(signed), []string{anchor.LogKey}, anchor.Origin, leaf[:], time.Unix(1, 0)); err == nil {
					t.Fatal("nonzero clock must expire deadline zero")
				} else if code, ok := CodeOf(err); !ok || code != Expired {
					t.Fatalf("nonzero clock: %v", err)
				}
				if _, err := Check(string(signed), []string{anchor.LogKey}, anchor.Origin, leaf[:], time.Time{}); err != nil {
					t.Fatalf("zero-clock repair: %v", err)
				}
				t.Log("nonzero clock expired; zero-clock repair accepted")
			}
			wrong := leaf
			wrong[0] ^= 1
			_, err = Check(string(signed), []string{anchor.LogKey}, anchor.Origin, wrong[:], time.Time{})
			if code, ok := CodeOf(err); !ok || code != Entry {
				t.Fatalf("wrong leaf: %v", err)
			}
			// Repairing only the caller's faulted leaf must accept the same note.
			if _, err := Check(string(signed), []string{anchor.LogKey}, anchor.Origin, leaf[:], time.Time{}); err != nil {
				t.Fatalf("leaf-only repair: %v", err)
			}
			t.Logf("deadline %d accepted; wrong leaf refused as entry; leaf-only repair accepted", deadline)
		})
	}
}
