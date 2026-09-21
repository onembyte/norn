package proof

import (
	"crypto/ed25519"
	"testing"

	"github.com/onembyte/norn/internal/tlog"
)

// Written from SPEC §8.1. A bundle is only worth shipping if someone holding
// nothing but norn.trust can check it, so every test here does exactly that:
// verify from the bundle alone, with no access to the log it came from.

func build(t *testing.T, size int) ([][]byte, *tlog.Tree, ed25519.PrivateKey, string) {
	t.Helper()
	entries := make([][]byte, 0, size)
	for i := 0; i < size; i++ {
		entries = append(entries, []byte{byte(i), byte(i >> 8), 0x2a})
	}
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	return entries, tree, key, "norn/proof-test"
}

func TestABundleChecksOutOnItsOwn(t *testing.T) {
	entries, tree, key, origin := build(t, 91)
	signed, err := tree.Checkpoint(origin).Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int64{0, 1, 45, 90} {
		p, err := tree.InclusionProof(index)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := Build("dev", index, entries[index], p, signed)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := bundle.Encode()
		if err != nil {
			t.Fatal(err)
		}
		back, err := Decode(raw)
		if err != nil {
			t.Fatalf("index %d: %v", index, err)
		}
		if err := back.Check(testAnchor(t, origin, key)); err != nil {
			t.Errorf("index %d: a valid bundle must check out: %v", index, err)
		}
	}
}

func TestABundleWithTheWrongEntryIsRefused(t *testing.T) {
	entries, tree, key, origin := build(t, 40)
	signed, _ := tree.Checkpoint(origin).Sign(key)
	p, _ := tree.InclusionProof(7)

	// The proof is genuine and the checkpoint is genuine -- only the entry has
	// been swapped. This is the substitution a bundle exists to make detectable.
	bundle, err := Build("dev", 7, entries[8], p, signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Check(testAnchor(t, origin, key)); err == nil {
		t.Error("a bundle whose entry does not match its proof must be refused")
	}
}

func TestABundleWithAForeignCheckpointIsRefused(t *testing.T) {
	entries, tree, key, origin := build(t, 40)
	p, _ := tree.InclusionProof(3)

	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 9))
	signed, _ := tree.Checkpoint(origin).Sign(other)

	bundle, _ := Build("dev", 3, entries[3], p, signed)
	if err := bundle.Check(testAnchor(t, origin, key)); err == nil {
		t.Error("a checkpoint signed by an untrusted key must be refused")
	}
}

func TestABundleWithATamperedProofIsRefused(t *testing.T) {
	entries, tree, key, origin := build(t, 40)
	signed, _ := tree.Checkpoint(origin).Sign(key)
	p, _ := tree.InclusionProof(5)

	bundle, _ := Build("dev", 5, entries[5], p, signed)
	if len(bundle.Proof) == 0 {
		t.Skip("no proof hashes to tamper with at this size")
	}
	bundle.Proof[0][0] ^= 0x01
	if err := bundle.Check(testAnchor(t, origin, key)); err == nil {
		t.Error("a bundle with an altered proof must be refused")
	}
}

func TestBundlesRoundTripCanonically(t *testing.T) {
	entries, tree, key, origin := build(t, 20)
	signed, _ := tree.Checkpoint(origin).Sign(key)
	p, _ := tree.InclusionProof(2)
	bundle, _ := Build("dev", 2, entries[2], p, signed)

	raw, err := bundle.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := back.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(again) {
		t.Error("a bundle must re-encode to the same bytes")
	}
}

func vkeyFor(origin string, key ed25519.PrivateKey) []string {
	return []string{noteKey(origin, key.Public().(ed25519.PublicKey))}
}

// testAnchor is the anchor these tests check against.
//
// They are about the inclusion proof and the encoding, not about
// corroboration, so the policy is `quorum none`: it requires no witness and
// keeps the checkpoints here uncosigned. The quorum rule §8.1 gained in
// 6.5h-iii is covered by `proofs-bad/no-quorum`, against the shipped anchor.
func testAnchor(t *testing.T, origin string, key ed25519.PrivateKey) Anchor {
	t.Helper()
	keys := vkeyFor(origin, key)
	return Anchor{Origin: origin, LogKey: keys[0],
		Policy: "log " + keys[0] + "\nquorum none\n"}
}
