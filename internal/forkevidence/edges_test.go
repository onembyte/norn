package forkevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/tlog"
)

// --- 6.5l-vii-d-i: two edges of §11.1 run 12 found unpinned ----------------
//
// D2. At the held checkpoint's own size there is no proof to check, and the
// one thing that binds `held_root` to anything is that it is the root `held`
// is signed over. §11.1's step 3 says so; its `proof` row did not, and no
// vector made a reader do it. A reader that skips it proves a fork from one
// honest checkpoint and any 32 bytes -- and §11 rule 4 makes that permanent.
//
// D3. §11.1 never said what `size` 0 means. No consistency proof starts at an
// empty tree (RFC 6962 §2.1.2 defines one only for 0 < m < n), and at size 0
// every log has the same root, so no file can show a disagreement there. A
// reader that lets an empty proof stand at size 0 proves a fork from any old
// cosigned size-0 head. Size 0 is `proof`, whatever the held size and
// whatever `held_root` says.

func TestAHeldRootThatIsNotHeldsOwnIsProof(t *testing.T) {
	_, heldSigned := branch(t, entriesNamed("mine-", 10))
	logVKey, _, policy := trustKeys(t)
	ev := &Evidence{Held: heldSigned, Conflicting: heldSigned, Size: 10,
		HeldRoot: bytes.Repeat([]byte{0x42}, 32), Policy: policy}
	_, err := Check(ev, origin, logVKey, policy)
	if got, _ := evrefusal.CodeOf(err); got != evrefusal.Proof {
		t.Errorf("refused as %q, want %q: %v", got, evrefusal.Proof, err)
	}
}

func TestSizeZeroIsProof(t *testing.T) {
	logVKey, _, policy := trustKeys(t)
	_, held10 := branch(t, entriesNamed("mine-", 10))
	_, empty := branch(t, nil)
	emptyRoot := sha256.Sum256(nil)
	for _, c := range []struct {
		name     string
		held     string
		heldRoot []byte
	}{
		{"any 32 bytes, a held branch of ten", held10, bytes.Repeat([]byte{0x42}, 32)},
		{"the empty root, a held branch of ten", held10, emptyRoot[:]},
		// Held is itself empty, so size equals the held size and there is no
		// proof to check: without a rule for size 0 this came out
		// `consistent` -- the right refusal for the wrong reason.
		{"the empty root, an empty held branch", empty, emptyRoot[:]},
	} {
		t.Run(c.name, func(t *testing.T) {
			ev := &Evidence{Held: c.held, Conflicting: empty, Size: 0,
				HeldRoot: c.heldRoot, Policy: policy}
			_, err := Check(ev, origin, logVKey, policy)
			if got, _ := evrefusal.CodeOf(err); got != evrefusal.Proof {
				t.Errorf("refused as %q, want %q: %v", got, evrefusal.Proof, err)
			}
		})
	}
}

// The shipped files for run 12's fork findings, each property computed from
// the bytes: a file at the held size whose held_root is not held's own (D2),
// a file at size 0 (D3), and bad-size-above-held refused by its own half of
// step 7 alone -- its conflicting head really is `size` entries, so the other
// half passes and only "above the held size" refuses it (D17).
func TestRunTwelvesForkFindingsHaveVectors(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	anchor := shippedAnchor(t, root)
	var doc struct {
		Codes map[string]evrefusal.Code `json:"codes"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "fork", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	parsed := func(name string) *Evidence {
		body, err := os.ReadFile(filepath.Join(root, "fork", name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		ev, err := Parse(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return ev
	}
	head := func(signed string) tlog.Checkpoint {
		cp, err := tlog.Verify(signed, []string{anchor.LogKey})
		if err != nil {
			t.Fatal(err)
		}
		return cp
	}
	var atHeldSize, atZero bool
	for name, code := range doc.Codes {
		if code != evrefusal.Proof {
			continue
		}
		ev := parsed(name)
		held := head(ev.Held)
		if ev.Size == held.Size && !bytes.Equal(ev.HeldRoot, held.Root[:]) {
			atHeldSize = true
		}
		if ev.Size == 0 {
			atZero = true
		}
	}
	if !atHeldSize {
		t.Error("no `proof` file is at the held size with a held_root that is not held's own (D2)")
	}
	if !atZero {
		t.Error("no `proof` file is at size 0 (D3)")
	}
	above := parsed("bad-size-above-held")
	if c := head(above.Conflicting); c.Size != above.Size {
		t.Errorf("bad-size-above-held's conflicting head is %d entries and its size is %d: "+
			"step 7's other half refuses it too, so its own rule is not isolated (D17)",
			c.Size, above.Size)
	}
	if above.Size <= head(above.Held).Size {
		t.Error("bad-size-above-held is not above the held size")
	}
}

// cases.json's `sound` names every file that MUST prove a fork, so a reader
// is held to the positives as well as the negatives. One is at a power-of-two
// size below the held one: RFC 6962's consistency proof has a branch for
// exactly that shape, and the only sound evidence was at 41 (D13a).
func TestEverySoundEvidenceFileProvesAFork(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	anchor := shippedAnchor(t, root)
	var doc struct {
		Sound []string `json:"sound"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "fork", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Sound) < 3 {
		t.Fatalf("cases.json names %d sound files; want the three this suite ships", len(doc.Sound))
	}
	var powerOfTwo bool
	for _, name := range doc.Sound {
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(root, "fork", name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			ev, err := Parse(body)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Check(ev, anchor.Origin, anchor.LogKey, anchor.Policy); err != nil {
				t.Fatalf("does not prove a fork: %v", err)
			}
			held, err := tlog.Verify(ev.Held, []string{anchor.LogKey})
			if err != nil {
				t.Fatal(err)
			}
			if ev.Size > 0 && ev.Size&(ev.Size-1) == 0 && ev.Size < held.Size {
				powerOfTwo = true
			}
		})
	}
	if !powerOfTwo {
		t.Error("no sound file is at a power-of-two size below the held one (D13a)")
	}
}
