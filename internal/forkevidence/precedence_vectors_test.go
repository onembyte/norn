package forkevidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
)

// Repairing either fault separately makes the ordering vector observable.
func TestTheAgreeingRootsVectorAlsoCarriesABadSplitProof(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	ev, err := Parse(read("fork/bad-consistent-and-bad-split.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor := shippedAnchor(t, root)
	keys := []string{anchor.LogKey}
	check := func(want evrefusal.Code) {
		t.Helper()
		_, err := Check(ev, anchor.Origin, keys, anchor.Policy)
		if got, _ := evrefusal.CodeOf(err); got != want {
			t.Fatalf("got %q (%v), want %q", got, err, want)
		}
	}
	if ev.Version != 2 || ev.Split == 0 {
		t.Fatal("the vector must carry a real version-2 split")
	}
	check(evrefusal.Proof)
	held, err := tlog.Verify(ev.Held, keys)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct{ Entries []struct{ Name string } }
	if err := json.Unmarshal(read("log/manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	var entries [][]byte
	for _, e := range manifest.Entries[:held.Size] {
		entries = append(entries, read("log/"+e.Name+".cbor"))
	}
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	repaired, err := treeProof(tree, ev.Split)
	if err != nil {
		t.Fatal(err)
	}
	if len(repaired) == 0 || len(repaired) != len(ev.SplitProofHeld) {
		t.Fatal("no held split proof hash to corrupt")
	}
	for i := range repaired {
		want := bytes.Clone(repaired[i])
		if i == 0 {
			want[0] ^= 1
		}
		if !bytes.Equal(want, ev.SplitProofHeld[i]) {
			t.Fatal("the held split proof differs by more than one corrupted hash byte")
		}
	}
	broken := ev.SplitProofHeld
	ev.SplitProofHeld = repaired
	check(evrefusal.Consistent)
	ev.SplitProofHeld = broken
	// Sign the same conflicting size with a different root under the shipped
	// public test keys. The corrupt held proof must still decide the refusal.
	cp, err := tlog.Verify(ev.Conflicting, keys)
	if err != nil {
		t.Fatal(err)
	}
	cp.Root[0] ^= 1
	fixtureKey := func(name string) ed25519.PrivateKey {
		seed := sha256.Sum256([]byte("norn/testvector/v1\n" + name))
		return ed25519.NewKeyFromSeed(seed[:])
	}
	ev.Conflicting, err = cp.Sign(fixtureKey("logkey"))
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := note.Split(ev.Conflicting)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pi", "vps", "friend"} {
		line, err := cosign.Sign(body, "norn-witness/"+name, fixtureKey("witness-"+name), time.Unix(1_760_003_600, 0))
		if err != nil {
			t.Fatal(err)
		}
		ev.Conflicting += line + "\n"
	}
	check(evrefusal.Proof)
}
