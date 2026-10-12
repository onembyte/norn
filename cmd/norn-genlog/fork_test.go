package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/trust"
)

// Rebuild both trees from the served entries and the generator's fork entry,
// rather than assuming the disagreement size is the common prefix. Each
// positive forkedBranch vector diverges at its last entry, not at its head.
func TestTheVectorsSplitIsRebuiltFromBothBranches(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	held, err := logclient.Verify(logclient.Dir(filepath.Join(root, "served")), logclient.Anchor{
		Anchor: replay.FromTrust(anchor),
		Origin: anchor.Origin, LogKeys: []string{anchor.LogKey}, Policy: anchor.Policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"evidence", "evidence-at-64", "evidence-at-same-size", "evidence-at-the-cap", "policy-not-the-readers"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, "fork", name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			ev, err := forkevidence.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			divergent, err := forkEntry(root, held.Served[:ev.Size-1])
			if err != nil {
				t.Fatal(err)
			}
			entries := append([][]byte(nil), held.Served[:ev.Size-1]...)
			entries = append(entries, divergent)
			conflicting, err := tlog.Build(entries)
			if err != nil {
				t.Fatal(err)
			}
			cp, err := tlog.Verify(ev.Conflicting, []string{anchor.LogKey})
			if err != nil {
				t.Fatal(err)
			}
			if conflicting.Head() != cp.Root {
				t.Fatal("reconstructed fork branch does not match the signed head")
			}
			var split int64
			for i, entry := range entries {
				if !bytes.Equal(entry, held.Served[i]) {
					break
				}
				split++
			}
			built, err := forkevidence.Build(held.Tree, conflicting, held.SignedCheckpoint, ev.Conflicting)
			if err != nil {
				t.Fatal(err)
			}
			want, err := held.Tree.HeadAt(split)
			if err != nil {
				t.Fatal(err)
			}
			if built.Split != split || ev.Split != split || !bytes.Equal(built.SplitRoot, want[:]) || !bytes.Equal(ev.SplitRoot, want[:]) {
				t.Fatalf("built split %d, vector split %d, entry prefix %d", built.Split, ev.Split, split)
			}
		})
	}
}
