package forkevidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/tlog"
)

// splitPair starts with a real fork and supplies independently computed split
// proofs, so the reader tests do not depend on Build finding the right prefix.
func splitPair(t *testing.T) (*Evidence, *tlog.Tree, *tlog.Tree) {
	t.Helper()
	common := entriesNamed("common-", 4)
	held, hs := branch(t, append(slices.Clone(common), entriesNamed("held-", 8)...))
	conflicting, cs := branch(t, append(slices.Clone(common), entriesNamed("conflicting-", 4)...))
	ev, err := Build(held, conflicting, hs, cs)
	if err != nil {
		t.Fatal(err)
	}
	_, _, ev.Policy = trustKeys(t)
	ev.Version = 2
	setSplit(t, ev, held, conflicting, 4)
	return ev, held, conflicting
}

func setSplit(t *testing.T, ev *Evidence, held, conflicting *tlog.Tree, at int64) {
	t.Helper()
	ev.Split = at
	ev.SplitRoot = make([]byte, 32)
	ev.SplitProofHeld, ev.SplitProofConflicting = nil, nil
	if at == 0 {
		return
	}
	root, err := held.HeadAt(at)
	if err != nil {
		t.Fatal(err)
	}
	copy(ev.SplitRoot, root[:])
	for tree, into := range map[*tlog.Tree]*[][]byte{held: &ev.SplitProofHeld, conflicting: &ev.SplitProofConflicting} {
		if at == tree.Size() {
			continue
		}
		proof, err := tree.ConsistencyProof(at)
		if err != nil {
			t.Fatal(err)
		}
		for _, hash := range proof {
			*into = append(*into, bytes.Clone(hash[:]))
		}
	}
}

func TestSplitProofsAreCheckedBeforeTheForkIsConcluded(t *testing.T) {
	good, held, conflicting := splitPair(t)
	key, _, pol := trustKeys(t)
	for _, tc := range []struct {
		name   string
		change func(*Evidence)
		want   evrefusal.Code
	}{
		{"above size", func(e *Evidence) { e.Split = e.Size + 1 }, evrefusal.Proof},
		{"held proof does not chain", func(e *Evidence) { e.SplitProofHeld = [][]byte{make([]byte, 32)} }, evrefusal.Proof},
		{"conflicting proof does not chain", func(e *Evidence) { e.SplitProofConflicting = [][]byte{make([]byte, 32)} }, evrefusal.Proof},
		{"zero with held proof", func(e *Evidence) { setSplit(t, e, held, conflicting, 0); e.SplitProofHeld = [][]byte{make([]byte, 32)} }, evrefusal.Proof},
		{"zero with conflicting proof", func(e *Evidence) {
			setSplit(t, e, held, conflicting, 0)
			e.SplitProofConflicting = [][]byte{make([]byte, 32)}
		}, evrefusal.Proof},
		{"zero with a root", func(e *Evidence) { setSplit(t, e, held, conflicting, 0); e.SplitRoot[0] = 1 }, evrefusal.Proof},
		{"bad split before consistent", func(e *Evidence) {
			e.Conflicting = e.Held
			e.Size = held.Size()
			e.HeldRoot = bytes.Clone(heldHead(t, held))
			e.Proof = nil
			e.Split = e.Size + 1
		}, evrefusal.Proof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := *good
			tc.change(&ev)
			_, err := Check(&ev, origin, []string{key}, pol)
			if code, _ := evrefusal.CodeOf(err); code != tc.want {
				t.Fatalf("got %q (%v), want %q", code, err, tc.want)
			}
		})
	}
	for _, at := range []int64{4, 3, 0} {
		ev := *good
		setSplit(t, &ev, held, conflicting, at)
		finding, err := Check(&ev, origin, []string{key}, pol)
		if err != nil {
			t.Fatal(err)
		}
		if finding.Split != at || !bytes.Equal(finding.SplitRoot[:], ev.SplitRoot) {
			t.Fatalf("split finding = %+v, want %d and %x", finding, at, ev.SplitRoot)
		}
	}
}

func heldHead(t *testing.T, tree *tlog.Tree) []byte { t.Helper(); h := tree.Head(); return h[:] }

func TestVersionTwoHasExactlyElevenTypedKeysAndVersionOneHasSeven(t *testing.T) {
	ev, _, _ := splitPair(t)
	raw, err := ev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc := value.(map[string]any)
	if doc["version"] != uint64(2) || len(doc) != 11 {
		t.Fatalf("encoded version %v with %d keys, want version 2 and eleven", doc["version"], len(doc))
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		want   evrefusal.Code
	}{
		{"twelve keys", func(m map[string]any) { m["surprise"] = "x" }, evrefusal.Schema},
		{"version three", func(m map[string]any) { m["version"] = uint64(3) }, evrefusal.Version},
		{"boolean split", func(m map[string]any) { m["split"] = true }, evrefusal.Schema},
		{"short root", func(m map[string]any) { m["split_root"] = make([]byte, 31) }, evrefusal.Schema},
		{"text root", func(m map[string]any) { m["split_root"] = "x" }, evrefusal.Schema},
		{"missing split", func(m map[string]any) { delete(m, "split") }, evrefusal.Schema},
		{"held proof type", func(m map[string]any) { m["split_proof_held"] = "x" }, evrefusal.Schema},
		{"conflicting proof type", func(m map[string]any) { m["split_proof_conflicting"] = false }, evrefusal.Schema},
		{"held hash length", func(m map[string]any) { m["split_proof_held"] = []any{make([]byte, 31)} }, evrefusal.Schema},
		{"conflicting hash type", func(m map[string]any) { m["split_proof_conflicting"] = []any{"x"} }, evrefusal.Schema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]any{}
			for k, v := range doc {
				m[k] = v
			}
			tc.change(m)
			b, err := cbor.Encode(m)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Parse(b)
			if code, _ := evrefusal.CodeOf(err); code != tc.want {
				t.Fatalf("got %q (%v), want %q", code, err, tc.want)
			}
		})
	}
	doc["version"] = uint64(1)
	for _, k := range []string{"split", "split_root", "split_proof_held", "split_proof_conflicting"} {
		delete(doc, k)
	}
	raw, err = cbor.Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	old, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if old.Version != 1 || old.Split != 0 || len(old.SplitRoot) != 0 || len(old.SplitProofHeld) != 0 || len(old.SplitProofConflicting) != 0 {
		t.Fatalf("version 1 claims a split: %+v", old)
	}
	key, _, pol := trustKeys(t)
	if finding, err := Check(old, origin, []string{key}, pol); err != nil || finding.Split != 0 {
		t.Fatalf("legacy evidence must prove the fork without a split: %+v, %v", finding, err)
	}
	upgraded, err := old.Encode()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := Parse(upgraded)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Version != 2 || fresh.Split != 0 || !bytes.Equal(fresh.SplitRoot, make([]byte, 32)) {
		t.Fatal("legacy Encode must upgrade to version 2 claiming no split")
	}
	doc["split"] = uint64(0)
	extra, err := cbor.Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(extra); err == nil {
		t.Fatal("version 1 must reject a split key")
	}

}

func TestBothEvidenceVersionsAndTheUnderstatedSplitAreVectored(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "fork", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Sound []string
		Codes map[string]evrefusal.Code
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	anchor := shippedAnchor(t, root)
	for _, name := range []string{"evidence", "evidence-at-64", "evidence-at-same-size", "evidence-at-the-cap", "policy-not-the-readers", "evidence-understated-split"} {
		names := []string{name}
		if name != "evidence-understated-split" {
			names = append(names, name+"-v1")
		}
		for _, n := range names {
			t.Run(n, func(t *testing.T) {
				if !slices.Contains(manifest.Sound, n) {
					t.Fatalf("sound does not name %s", n)
				}
				raw, err := os.ReadFile(filepath.Join(root, "fork", n+".cbor"))
				if err != nil {
					t.Fatal(err)
				}
				ev, err := Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				finding, err := Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasSuffix(n, "-v1") && finding.Split == 0 {
					t.Fatal("version 2 vector claims no split")
				}
				if strings.HasSuffix(n, "-v1") && (ev.Version != 1 || finding.Split != 0) {
					t.Fatal("legacy vector must prove the fork, claims no split")
				}
			})
		}
	}
	for _, name := range []string{"bad-split-above-size", "bad-split-proof-held", "bad-split-proof-conflicting", "bad-split-zero-with-a-proof", "bad-split-root-length", "bad-twelve-keys", "bad-version-three"} {
		if _, ok := manifest.Codes[name]; !ok {
			t.Errorf("new refusal not vectored: %s", name)
		}
	}
}

// A genuine fork's common prefix is below both heads. Exercise the shared
// proof checker at a head's own size as well, where only the signature binds
// the root and carrying any proof is forbidden.
func TestASplitAtAHeadsOwnSizeNeedsItsRootAndNoProof(t *testing.T) {
	tree, _ := branch(t, entriesNamed("common-", 4))
	cp := tree.Checkpoint(origin)
	root := tree.Head()
	if err := checkSplitProof("held", tree.Size(), root, nil, cp); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		root  [32]byte
		proof [][]byte
	}{
		{"proof carried", root, [][]byte{make([]byte, 32)}},
		{"root not signed", [32]byte{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSplitProof("conflicting", tree.Size(), tc.root, tc.proof, cp)
			if code, _ := evrefusal.CodeOf(err); code != evrefusal.Proof {
				t.Fatalf("got %q (%v), want proof", code, err)
			}
		})
	}
}

func TestBuildFindsTheCommonPrefixIncludingNoSharedEntry(t *testing.T) {
	for _, at := range []int{0, 1, 4, 8} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			common := entriesNamed("common-", at)
			held, hs := branch(t, append(slices.Clone(common), entriesNamed("held-", 8)...))
			conflicting, cs := branch(t, append(slices.Clone(common), entriesNamed("conflicting-", 4)...))
			ev, err := Build(held, conflicting, hs, cs)
			if err != nil {
				t.Fatal(err)
			}
			if ev.Version != 2 || ev.Split != int64(at) {
				t.Fatalf("version %d split %d, want 2 and %d", ev.Version, ev.Split, at)
			}
			key, _, pol := trustKeys(t)
			ev.Policy = pol
			finding, err := Check(ev, origin, []string{key}, pol)
			if err != nil {
				t.Fatal(err)
			}
			if finding.Split != int64(at) {
				t.Fatalf("finding split %d, want %d", finding.Split, at)
			}
			if at == 0 && (!bytes.Equal(ev.SplitRoot, make([]byte, 32)) || len(ev.SplitProofHeld) != 0 || len(ev.SplitProofConflicting) != 0) {
				t.Fatal("no shared entries must claim no prefix")
			}
		})
	}
}
