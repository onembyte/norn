package forkevidence

import (
	"bytes"
	"testing"

	"github.com/onembyte/norn/internal/evrefusal"
)

// A valid common prefix is independent of whether the signed roots disagree.
// D-076 requires every carried proof to pass before that comparison.
func TestABadSplitProofPrecedesAgreeingRoots(t *testing.T) {
	entries := entriesNamed("shared-", 12)
	held, hs := branch(t, entries)
	prefix, ps := branch(t, entries[:8])
	root, err := held.HeadAt(8)
	if err != nil {
		t.Fatal(err)
	}
	key, _, pol := trustKeys(t)
	ev := &Evidence{Version: 2, Held: hs, Conflicting: ps, Size: 8, HeldRoot: bytes.Clone(root[:]), Policy: pol}
	ev.Proof, err = treeProof(held, 8)
	if err != nil {
		t.Fatal(err)
	}
	setSplit(t, ev, held, prefix, 4)
	ev.SplitProofHeld[0][0] ^= 1
	_, err = Check(ev, origin, []string{key}, pol)
	if got, _ := evrefusal.CodeOf(err); got != evrefusal.Proof {
		t.Fatalf("two faults refused as %q, want proof: %v", got, err)
	}
}
