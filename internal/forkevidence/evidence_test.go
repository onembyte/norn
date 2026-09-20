package forkevidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
)

// `GOSSIP.md` part 7: fork evidence "is the artifact that goes to the witness
// operators, the log operator's boss, or a blog post". So the bar is not "this
// node is convinced" -- it is that somebody with `norn.trust`, no running
// network and no reason to trust the accuser can check it offline and see the
// log signed two different histories.
//
// Two signed heads are not enough on their own when their sizes differ: at
// different sizes, different roots are *expected*. What makes it a fork is a
// proof that the larger head's own tree had a different root at the smaller
// head's size than the smaller head claims -- and that proof chains to a head
// the log signed, so it cannot be fabricated by whoever is complaining.

const origin = "norn/fork-test"

func logKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/fork-test/log"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func witnessKey(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/fork-test/witness/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func trustKeys(t *testing.T) (logVKey string, witnessVKeys []string, policy string) {
	t.Helper()
	logVKey = note.VerifierKey(origin, logKey(t).Public().(ed25519.PublicKey))
	var b strings.Builder
	b.WriteString("log " + origin + " " + logVKey + "\n")
	for _, name := range []string{"pi", "vps"} {
		vkey := note.CosignerVerifierKey("norn-witness/"+name,
			witnessKey(t, name).Public().(ed25519.PublicKey))
		witnessVKeys = append(witnessVKeys, vkey)
		b.WriteString("witness " + name + " " + vkey + "\n")
	}
	b.WriteString("group all 2 pi vps\nquorum all\n")
	return logVKey, witnessVKeys, b.String()
}

// branch builds a log over `entries` and returns its tree and a signed,
// cosigned head at the current size.
func branch(t *testing.T, entries [][]byte) (*tlog.Tree, string) {
	t.Helper()
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := tree.Checkpoint(origin).Sign(logKey(t))
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

// headOf is the parsed head of a checkpoint this test signed itself.
func headOf(t *testing.T, signed string) tlog.Checkpoint {
	t.Helper()
	cp, err := tlog.Verify(signed, []string{
		note.VerifierKey(origin, logKey(t).Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func entriesNamed(prefix string, n int) [][]byte {
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, []byte(prefix+string(rune('a'+i))))
	}
	return out
}

// The case a node actually hits: it holds a long branch, and somebody serves a
// shorter head whose history is not this log's history.
func TestEvidenceProvesEquivocationAtDifferentSizes(t *testing.T) {
	mine, mineSigned := branch(t, entriesNamed("mine-", 20))
	_, theirsSigned := branch(t, entriesNamed("theirs-", 10))

	ev, err := Build(mine, mineSigned, theirsSigned, headOf(t, theirsSigned))
	if err != nil {
		t.Fatal(err)
	}
	logVKey, witnessVKeys, policy := trustKeys(t)
	ev.Policy = policy

	finding, err := Check(ev, origin, logVKey, witnessVKeys)
	if err != nil {
		t.Fatalf("evidence a node produced does not check out: %v", err)
	}
	if finding.Size != 10 {
		t.Errorf("the disagreement is at size %d, want 10", finding.Size)
	}
	if finding.Held == finding.Claimed {
		t.Error("evidence with two identical roots proves nothing")
	}
}

// The simplest fork: two heads of the same size with different roots. No proof
// is needed, because the two signatures say it on their own.
func TestEvidenceAtTheSameSizeNeedsNoProof(t *testing.T) {
	mine, mineSigned := branch(t, entriesNamed("mine-", 10))
	_, theirsSigned := branch(t, entriesNamed("theirs-", 10))

	ev, err := Build(mine, mineSigned, theirsSigned, headOf(t, theirsSigned))
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Proof) != 0 {
		t.Errorf("a same-size fork needs no consistency proof, got %d hashes", len(ev.Proof))
	}
	logVKey, witnessVKeys, policy := trustKeys(t)
	ev.Policy = policy
	if _, err := Check(ev, origin, logVKey, witnessVKeys); err != nil {
		t.Fatalf("same-size evidence does not check out: %v", err)
	}
}

// Two consistent heads are not evidence of anything, and a node must not be
// able to produce a file claiming they are.
func TestConsistentHeadsAreNotEvidence(t *testing.T) {
	mine, mineSigned := branch(t, entriesNamed("mine-", 20))
	shorter, shorterSigned := branch(t, entriesNamed("mine-", 10))
	_ = shorter

	if _, err := Build(mine, mineSigned, shorterSigned, headOf(t, shorterSigned)); err == nil {
		t.Fatal("a fork was claimed between a log and its own earlier self")
	}
}

// The checks a third party makes, each of which some fabricated file would
// otherwise pass.
func TestFabricatedEvidenceIsRefused(t *testing.T) {
	mine, mineSigned := branch(t, entriesNamed("mine-", 20))
	_, theirsSigned := branch(t, entriesNamed("theirs-", 10))
	logVKey, witnessVKeys, policy := trustKeys(t)

	good, err := Build(mine, mineSigned, theirsSigned, headOf(t, theirsSigned))
	if err != nil {
		t.Fatal(err)
	}
	good.Policy = policy

	t.Run("a head signed by another key", func(t *testing.T) {
		other := ed25519.NewKeyFromSeed(make([]byte, 32))
		tree, _ := branch(t, entriesNamed("theirs-", 10))
		forged, err := tree.Checkpoint(origin).Sign(other)
		if err != nil {
			t.Fatal(err)
		}
		ev := *good
		ev.Conflicting = forged
		if _, err := Check(&ev, origin, logVKey, witnessVKeys); err == nil {
			t.Error("a head this network's log never signed was accepted as evidence")
		}
	})

	t.Run("a head no quorum cosigned", func(t *testing.T) {
		tree, _ := branch(t, entriesNamed("theirs-", 10))
		bare, err := tree.Checkpoint(origin).Sign(logKey(t))
		if err != nil {
			t.Fatal(err)
		}
		ev := *good
		ev.Conflicting = bare
		if _, err := Check(&ev, origin, logVKey, witnessVKeys); err == nil {
			t.Error("a head no witness vouched for was accepted; the log alone " +
				"signing two things is not equivocation anybody else can see")
		}
	})

	t.Run("a made-up consistency proof", func(t *testing.T) {
		ev := *good
		ev.Proof = append([][]byte(nil), good.Proof...)
		if len(ev.Proof) == 0 {
			t.Skip("no proof at this size")
		}
		ev.Proof[0] = make([]byte, 32)
		if _, err := Check(&ev, origin, logVKey, witnessVKeys); err == nil {
			t.Error("a proof that does not chain to the signed head was accepted")
		}
	})

	t.Run("another network's origin", func(t *testing.T) {
		if _, err := Check(good, "norn/somebody-else", logVKey, witnessVKeys); err == nil {
			t.Error("evidence was accepted against the wrong network's anchor")
		}
	})
}

// It round-trips through a file, because it is a file that gets emailed.
func TestEvidenceRoundTripsThroughAFile(t *testing.T) {
	mine, mineSigned := branch(t, entriesNamed("mine-", 20))
	_, theirsSigned := branch(t, entriesNamed("theirs-", 10))
	ev, err := Build(mine, mineSigned, theirsSigned, headOf(t, theirsSigned))
	if err != nil {
		t.Fatal(err)
	}
	logVKey, witnessVKeys, policy := trustKeys(t)
	ev.Policy = policy

	path := filepath.Join(t.TempDir(), "1760000000.evidence")
	raw, err := ev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	back, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(back, origin, logVKey, witnessVKeys); err != nil {
		t.Fatalf("evidence stopped checking out after a round trip: %v", err)
	}
}
