package forkevidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/policy"
)

var runTwentyOneEvidence = []string{"bad-bool-version", "bad-split-held-root-at-own-size", "bad-split-conflicting-root-at-own-size"}

func runTwentyOneEvidenceName(name string) bool {
	for _, n := range runTwentyOneEvidence {
		if n == name {
			return true
		}
	}
	return false
}
func runTwentyOneRead(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "fork", name))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func runTwentyOneMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	v, e := cbor.DecodeWithin(b, MaxEvidenceBytes)
	if e != nil {
		t.Fatal(e)
	}
	return v.(map[string]any)
}
func checkRunTwentyOneEvidencePairs(t *testing.T) {
	t.Helper()
	for _, name := range runTwentyOneEvidence {
		t.Run(name, func(t *testing.T) { checkRunTwentyOneEvidencePair(t, name) })
	}
}
func TestBothSplitEndpointsAtTheirOwnSizeHaveTheirVectors(t *testing.T) {
	checkRunTwentyOneEvidencePairs(t)
}

func checkRunTwentyOneEvidencePair(t *testing.T, name string) {
	t.Helper()
	var meta struct {
		Cases []struct{ Name string }
		Codes map[string]string
		Rules map[string]struct{ Section, Says string }
	}
	if e := json.Unmarshal(runTwentyOneRead(t, "cases.json"), &meta); e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range meta.Cases {
		if c.Name == name {
			count++
		}
	}
	code, phrase := "proof", "each as step 3 does, with the same empty-proof rule at a head's own size."
	if name == "bad-bool-version" {
		code, phrase = "version", "absent, not a uint, or another number"
	}
	if count != 1 || meta.Codes[name] != code || meta.Rules[name].Section != "11.1" || meta.Rules[name].Says != phrase {
		t.Fatalf("missing %s case, code or rule", name)
	}
	raw := runTwentyOneRead(t, name+".cbor")
	m := runTwentyOneMap(t, raw)
	a := shippedAnchor(t, filepath.Join("..", "..", "testdata", "vectors"))
	ev, e := Parse(raw)
	checkErr := e
	if name == "bad-bool-version" {
		if len(m) != 7 || m["version"] != true {
			t.Fatal("boolean version must retain v1's seven keys")
		}
	} else {
		if e != nil {
			t.Fatal(e)
		}
		if len(m) != 11 || ev.Version != 2 {
			t.Fatal("split cases require exactly eleven v2 keys")
		}
		rules, e := policy.Parse(a.Policy)
		if e != nil {
			t.Fatal(e)
		}
		h, e := verified(ev.Held, a.Origin, []string{a.LogKey}, rules)
		if e != nil {
			t.Fatal(e)
		}
		c, e := verified(ev.Conflicting, a.Origin, []string{a.LogKey}, rules)
		if e != nil {
			t.Fatal(e)
		}
		if h.Size != 162 || h.Size != c.Size || ev.Size != h.Size || ev.Split != h.Size || h.Root == c.Root || !bytes.Equal(ev.HeldRoot, h.Root[:]) || len(ev.Proof) != 0 || len(ev.SplitProofHeld) != 0 || len(ev.SplitProofConflicting) != 0 {
			t.Fatal("must isolate split roots at two genuine differing heads' common size")
		}
		var root [32]byte
		copy(root[:], ev.SplitRoot)
		he, ce := checkSplitProof("held", ev.Split, root, ev.SplitProofHeld, h), checkSplitProof("conflicting", ev.Split, root, ev.SplitProofConflicting, c)
		bad, good := he, ce
		right := h.Root
		other := c.Root
		if name == "bad-split-conflicting-root-at-own-size" {
			bad, good = ce, he
			right = c.Root
			other = h.Root
		}
		if got, _ := evrefusal.CodeOf(bad); got != evrefusal.Proof || good != nil || root != other {
			t.Fatalf("only named endpoint must fail: held=%v conflicting=%v", he, ce)
		}
		endpoint := h
		if name == "bad-split-conflicting-root-at-own-size" {
			endpoint = c
		}
		if e := checkSplitProof("repair", ev.Split, right, nil, endpoint); e != nil {
			t.Fatalf("endpoint-only root repair: %v", e)
		}
		_, checkErr = Check(ev, a.Origin, []string{a.LogKey}, a.Policy)
	}
	if got, _ := evrefusal.CodeOf(checkErr); string(got) != code {
		t.Fatalf("got %q, want %s: %v", got, code, checkErr)
	}
}

// Restoring the parent's four split fields repairs the whole accusation.
// Replacing one root alone cannot make two differing full-size roots agree.
func TestRunTwentyOneEvidenceRepairsRecoverTheirSoundParents(t *testing.T) {
	a := shippedAnchor(t, filepath.Join("..", "..", "testdata", "vectors"))
	for _, name := range runTwentyOneEvidence {
		t.Run(name, func(t *testing.T) {
			m := runTwentyOneMap(t, runTwentyOneRead(t, name+".cbor"))
			parent := "evidence-at-same-size.cbor"
			if name == "bad-bool-version" {
				parent = "evidence-v1.cbor"
				m["version"] = uint64(1)
			} else {
				p := runTwentyOneMap(t, runTwentyOneRead(t, parent))
				for _, k := range []string{"split", "split_root", "split_proof_held", "split_proof_conflicting"} {
					m[k] = p[k]
				}
			}
			raw, e := cbor.Encode(m)
			if e != nil || !bytes.Equal(raw, runTwentyOneRead(t, parent)) {
				t.Fatal("repair must recover sound parent byte for byte")
			}
			ev, e := Parse(raw)
			if e != nil {
				t.Fatal(e)
			}
			if _, e := Check(ev, a.Origin, []string{a.LogKey}, a.Policy); e != nil {
				t.Fatal(e)
			}
			t.Log("sound parent recovered byte for byte; fork proved")
		})
	}
}
