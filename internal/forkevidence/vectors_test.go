package forkevidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/policy"
)

// Cold-model gate run 5, defect G6. §12.1 claimed two refusals for §11 --
// "evidence for another origin is refused; so is a `fork` between a log and
// its own earlier self" -- and neither shipped as a file. The first is
// exercised by a Go test against the *valid* vector; the second could not be
// exercised at all, because `Build` refuses to produce it. A reader could not
// check either, and run 5 could not check the evidence vector at all, because
// the format it uses is not defined in SPEC.md.

func TestEveryForkNegativeIsRefused(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "fork", "cases.json"))
	if err != nil {
		t.Fatalf("the fork negatives are missing: %v", err)
	}
	var doc struct {
		Cases []struct{ Name, About string } `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 2 {
		t.Fatalf("%d fork negatives; §12.1 names two", len(doc.Cases))
	}

	anchor := shippedAnchor(t, root)

	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(root, "fork", c.Name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			// A negative may fail at either layer: the file may not parse, or
			// it may parse and prove nothing. Both are refusals; neither is an
			// accusation a third party should act on.
			evidence, err := Parse(body)
			if err != nil {
				if !strings.Contains(err.Error(), c.About) {
					t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.About)
				}
				return
			}
			_, err = Check(evidence, anchor.Origin, anchor.LogKey, anchor.Policy)
			if err == nil {
				t.Fatal("accepted evidence that proves no fork; a reader would act on a " +
					"false accusation")
			}
			if !strings.Contains(err.Error(), c.About) {
				t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.About)
			}
		})
	}
}

// Cold-model gate run 6, defect H1. §11.1 orders four MUSTs for a reader, and
// the two negatives shipped in 6.5e-i both landed on steps 1 and 4. Three
// variants -- never verifying the *conflicting* checkpoint, never checking the
// size equality, and never checking the consistency proof -- each passed
// 285/285. The acceptance path exercises the non-degenerate proof branch, so
// the suite forced a reader to *not reject* a valid proof and never once
// forced it to reject an invalid one.
//
// That matters more here than anywhere else in the protocol: §11 rule 4 makes
// a concluded FORK permanent until an operator ships a new trust file, so a
// forged accusation any stranger can write is a permanent denial of service.

// reaches reports which of §11.1's steps a case gets past, by checking the
// pieces a reader checks, in the order a reader checks them.
func reaches(t *testing.T, name string) (heldOK, conflictingOK, sizesAgree bool) {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "fork", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := Parse(raw)
	if err != nil {
		t.Fatalf("%s does not parse, so it tests parsing rather than a reader step: %v", name, err)
	}
	anchor := shippedAnchor(t, root)
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		t.Fatal(err)
	}
	_, heldErr := verified(ev.Held, anchor.Origin, anchor.LogKey, rules)
	conflicting, conflictingErr := verified(ev.Conflicting, anchor.Origin, anchor.LogKey, rules)
	return heldErr == nil, conflictingErr == nil,
		conflictingErr == nil && conflicting.Size == ev.Size
}

func TestEachForkNegativeReachesADifferentStep(t *testing.T) {
	// A forged proof must get past steps 1 and 2 to test step 3 at all.
	heldOK, conflictingOK, sizesAgree := reaches(t, "bad-forged-proof")
	if !heldOK || !conflictingOK {
		t.Error("bad-forged-proof carries a checkpoint that does not verify, so step 1 " +
			"refuses it and the consistency proof is never reached")
	}
	if !sizesAgree {
		t.Error("bad-forged-proof disagrees about the size, so step 2 refuses it and the " +
			"consistency proof is never reached")
	}

	// An unverifiable conflicting head must leave the *held* one intact, or it
	// is the case already covered by bad-other-origin.
	heldOK, conflictingOK, _ = reaches(t, "bad-unverifiable-conflicting")
	if !heldOK {
		t.Error("bad-unverifiable-conflicting fails on the held checkpoint, which is the " +
			"half bad-other-origin already covers")
	}
	if conflictingOK {
		t.Error("the conflicting checkpoint verifies, so nothing here tests that a reader " +
			"checks it")
	}

	// A size mismatch must get past step 1 on both sides.
	heldOK, conflictingOK, sizesAgree = reaches(t, "bad-size-mismatch")
	if !heldOK || !conflictingOK {
		t.Error("bad-size-mismatch carries a checkpoint that does not verify, so step 2 is " +
			"never reached")
	}
	if sizesAgree {
		t.Error("the sizes agree, so step 2 has nothing to refuse")
	}
}

// --- Cold-model gate run 8, defect D25 ----------------------------------
//
// §11.1 says evidence is "a closed map of exactly these seven keys". `Parse`
// read the seven it wanted and ignored anything else, so the closed-map rule
// was prose only — `evidence-open-schema` passed the whole suite because no
// file ever carried an eighth key.
//
// `size` had no stated bound either. An accuser can only speak for sizes its
// own branch reaches, so a `size` above `held`'s was refused by the consistency
// proof rather than by a rule, with a message about the proof.

func TestEveryEvidenceSchemaRuleHasItsCase(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	anchor := shippedAnchor(t, root)
	for _, want := range []string{"bad-open-schema", "bad-wrong-version", "bad-size-above-held"} {
		t.Run(want, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, "fork", want+".cbor"))
			if err != nil {
				t.Fatalf("§11.1 states this rule and no vector reaches it: %v", err)
			}
			ev, err := Parse(raw)
			if err != nil {
				return // refused by the schema, which is a refusal
			}
			if _, err := Check(ev, anchor.Origin, anchor.LogKey, anchor.Policy); err == nil {
				t.Errorf("%s was accepted; §11.1 says it must not be", want)
			}
		})
	}
}
