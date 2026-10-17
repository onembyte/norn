package forkevidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
)

// D-080 (2), row 6.5l-xv-f. A log that rotated its key and then equivocated
// signs both heads with the new key. A reader holding only the trust file does
// not trust that key and answers `held`, which is the truth; a reader that
// learned the key by replaying the rotation proves the fork. §11.1 step 1
// names the keys the reader trusts (§9.4), so the two readers differ only in
// what they hold, never in how they read the rule (cold gate run 17, D2).
func TestEvidenceUnderARotatedKeyIsProvedByTheReaderThatLearnedIt(t *testing.T) {
	seed := sha256.Sum256([]byte("norn/fork-test/log2"))
	rotated := ed25519.NewKeyFromSeed(seed[:])
	mine, mineSigned := branchSignedBy(t, entriesNamed("mine-", 20), rotated)
	theirs, theirsSigned := branchSignedBy(t, entriesNamed("theirs-", 10), rotated)
	ev, err := Build(mine, theirs, mineSigned, theirsSigned)
	if err != nil {
		t.Fatal(err)
	}
	trustKey, _, policy := trustKeys(t)
	ev.Policy = policy
	learned := note.VerifierKey(origin, rotated.Public().(ed25519.PublicKey))

	_, err = Check(ev, origin, []string{trustKey}, policy)
	if code, _ := evrefusal.CodeOf(err); code != evrefusal.Held {
		t.Fatalf("a reader holding only the trust file answers %q (%v), SPEC states held", code, err)
	}
	finding, err := Check(ev, origin, []string{trustKey, learned}, policy)
	if err != nil {
		t.Fatalf("a reader that learned the rotated key must prove the fork: %v", err)
	}
	if finding.Size != 10 {
		t.Errorf("the disagreement is at size %d, want 10", finding.Size)
	}
}

// branchSignedBy is branch with the log key given: the heads a rotated log
// signs.
func branchSignedBy(t *testing.T, entries [][]byte, key ed25519.PrivateKey) (*tlog.Tree, string) {
	t.Helper()
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := tree.Checkpoint(origin).Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := note.Split(signed)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pi", "vps"} {
		line, err := cosign.Sign(body, "norn-witness/"+name, witnessKey(t, name),
			time.Unix(1_760_003_600, 0))
		if err != nil {
			t.Fatal(err)
		}
		signed += line + "\n"
	}
	return tree, signed
}
