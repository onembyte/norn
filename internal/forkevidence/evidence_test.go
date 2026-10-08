package forkevidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/trust"
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
	b.WriteString("log " + logVKey + "\n")
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
	logVKey, _, policy := trustKeys(t)
	ev.Policy = policy

	finding, err := Check(ev, origin, []string{logVKey}, policy)
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
	logVKey, _, policy := trustKeys(t)
	ev.Policy = policy
	if _, err := Check(ev, origin, []string{logVKey}, policy); err != nil {
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
	logVKey, _, policy := trustKeys(t)

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
		if _, err := Check(&ev, origin, []string{logVKey}, policy); err == nil {
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
		if _, err := Check(&ev, origin, []string{logVKey}, policy); err == nil {
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
		if _, err := Check(&ev, origin, []string{logVKey}, policy); err == nil {
			t.Error("a proof that does not chain to the signed head was accepted")
		}
	})

	t.Run("another network's origin", func(t *testing.T) {
		if _, err := Check(good, "norn/somebody-else", []string{logVKey}, policy); err == nil {
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
	logVKey, _, policy := trustKeys(t)
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
	if _, err := Check(back, origin, []string{logVKey}, policy); err != nil {
		t.Fatalf("evidence stopped checking out after a round trip: %v", err)
	}
}

// The shipped vector. §12.1 owed this from Phase 4: without it a second
// implementation has nothing to check its evidence reader against -- and
// evidence is the artifact `GOSSIP.md` sends to witness operators and blog
// posts, so it is the last thing that should only ever be produced by the
// implementation that reads it.
//
// This checks it the way a stranger would: the committed file, the committed
// trust document, and nothing else.
func TestTheShippedVectorProvesAFork(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "fork", "evidence.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := Parse(raw)
	if err != nil {
		t.Fatalf("the shipped evidence does not parse: %v", err)
	}

	anchor := shippedAnchor(t, root)
	finding, err := Check(evidence, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
	if err != nil {
		t.Fatalf("the shipped evidence does not prove a fork: %v", err)
	}
	if finding.Held == finding.Claimed {
		t.Error("the two roots are the same, so nothing is proved")
	}
	// The conflicting head ships beside it, so a reader can see what the
	// evidence is about without decoding anything.
	conflicting, err := os.ReadFile(filepath.Join(root, "fork", "conflicting.checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if string(conflicting) != evidence.Conflicting {
		t.Error("the checkpoint shipped beside the evidence is not the one in it")
	}
}

// And it must be refused against any other network's anchor.
func TestTheShippedVectorIsRefusedElsewhere(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "fork", "evidence.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	anchor := shippedAnchor(t, root)
	if _, err := Check(evidence, "norn/somebody-else", []string{anchor.LogKey}, anchor.Policy); err == nil {
		t.Error("the vector was accepted against another network's origin")
	}
}

func shippedAnchor(t *testing.T, root string) *trust.Trust {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// --- Cold-model gate run 7, defect J12 ----------------------------------
//
// §11.1 gave the `policy` field no validation rule at all, and `Check` then
// verified **both checkpoints** under it. The witness *keys* came from the
// reader's trust file and the *quorum* came from the accuser's file, which is
// the split that made this easy to miss.
//
// The consequence is not subtle. §11.1 opens by saying a reader has "no reason
// to trust whoever handed them the file", and §11 rule 4 makes a fork
// conclusion permanent until an operator installs a new trust file. An accuser
// who writes `quorum none` therefore gets two uncosigned checkpoints accepted
// as proof of equivocation, and takes the network down until a human
// intervenes -- from a file, with no keys and no access to anything.
//
// The rule now: a reader verifies under **its own** policy, and the carried
// one is informational. It MUST parse, because a closed schema with a stated
// grammar is part of the format, and it MUST NOT decide anything.

func TestTheReadersOwnPolicyDecidesTheQuorum(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "fork", "bad-policy-says-quorum-none.cbor"))
	if err != nil {
		t.Fatalf("no vector for an accuser-chosen quorum: %v", err)
	}
	ev, err := Parse(raw)
	if err != nil {
		t.Fatalf("the case must decode, or it tests the codec: %v", err)
	}
	// The file's own policy has to be the permissive one, or the case is
	// about something else.
	if !strings.Contains(ev.Policy, "quorum none") {
		t.Errorf("the carried policy is not the permissive one this case is about")
	}
	anchor := shippedAnchor(t, root)
	if _, err := Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy); err == nil {
		t.Fatal("concluded a fork from two checkpoints no quorum cosigned, because " +
			"the accuser's own file said no quorum was needed")
	}
}

// The other direction: a policy the reader does not share must not break
// evidence that is otherwise sound. The field is informational, so a reader
// that verified under it would refuse a real fork -- and §11 rule 1 requires
// the alarm.
func TestAForeignPolicyFieldDoesNotBreakSoundEvidence(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "fork", "policy-not-the-readers.cbor"))
	if err != nil {
		t.Fatalf("no vector for a carried policy the reader does not share: %v", err)
	}
	ev, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	anchor := shippedAnchor(t, root)
	if ev.Policy == anchor.Policy {
		t.Error("the carried policy is the reader's own, so the case pins nothing")
	}
	if _, err := Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy); err != nil {
		t.Fatalf("refused sound evidence because of a field it must not verify "+
			"under: %v", err)
	}
}

func TestEvidenceWitnessesSharingANoteNameKeepTheirOwnLabels(t *testing.T) {
	const name = "norn-witness/shared"
	for _, tc := range []struct {
		name   string
		labels []string
		tail   string
		want   bool
	}{
		{"both meet two", []string{"a", "b"}, "group g 2 a b\nquorum g\n", true},
		{"b alone is short of two", []string{"b"}, "group g 2 a b\nquorum g\n", false},
		{"b cannot stand for a", []string{"b"}, "quorum a\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := fmt.Sprintf("witness a %s\nwitness b %s\n%s",
				note.CosignerVerifierKey(name, witnessKey(t, "a").Public().(ed25519.PublicKey)),
				note.CosignerVerifierKey(name, witnessKey(t, "b").Public().(ed25519.PublicKey)), tc.tail)
			rules, err := policy.Parse(text)
			if err != nil {
				t.Fatal(err)
			}
			tree, _ := branch(t, entriesNamed("mine-", 10))
			signed, err := tree.Checkpoint(origin).Sign(logKey(t))
			if err != nil {
				t.Fatal(err)
			}
			var signers []cosign.Signer
			for _, label := range tc.labels {
				signers = append(signers, cosign.Signer{Name: name, Key: witnessKey(t, label)})
			}
			signed, err = cosign.Append(signers, cosign.At(time.Unix(1_760_003_600, 0)))(signed)
			if err != nil {
				t.Fatal(err)
			}
			logVKey := note.VerifierKey(origin, logKey(t).Public().(ed25519.PublicKey))
			_, err = verified(signed, origin, []string{logVKey}, rules)
			if tc.want {
				if err != nil {
					t.Fatalf("a and b were refused: %v", err)
				}
			} else if code, _ := refusal.CodeOf(err); code != refusal.Quorum {
				t.Fatalf("evidence checkpoint refusal = %q (%v), want quorum", code, err)
			}
		})
	}
}
