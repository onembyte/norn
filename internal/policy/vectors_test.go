package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Cold-model gate run 8, defect D12 ----------------------------------
//
// §9.1 restates the `tlog-policy` grammar "because a verifier cannot be
// written without it", and the restatement was not enough to write one that
// *agrees*: run 8 flipped nine readings and every one of them passed the whole
// suite, because the only policy text in the vectors was the fixture's own and
// one negative that is not a policy at all.
//
// Six of the nine were not open questions but live disagreements between the
// two implementations in this repository — a whitespace-only line, a `#`
// comment, a vertical tab as a separator, a duplicate witness name, a forward
// reference, and a `group` with no members. Each parsed in one and was refused
// by the other, and nothing could see it.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

type policyCase struct {
	Name   string `json:"name"`
	Accept bool   `json:"accept"`
	Why    string `json:"why"`
}

func policyCases(t *testing.T) []policyCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "policies", "cases.json"))
	if err != nil {
		t.Fatalf("the policy-grammar vectors are missing: %v", err)
	}
	var doc struct {
		Cases []policyCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

func TestEveryPolicyGrammarCaseIsDecidedTheSameWay(t *testing.T) {
	cases := policyCases(t)
	var accepted, refused int
	for _, c := range cases {
		if c.Accept {
			accepted++
		} else {
			refused++
		}
	}
	if accepted < 3 || refused < 6 {
		t.Fatalf("%d accepted and %d refused; the grammar needs both sides of each "+
			"rule, or a parser enforcing the opposite passes", accepted, refused)
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(vectorRoot(), "policies", c.Name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = Parse(string(body))
			switch {
			case c.Accept && err != nil:
				t.Errorf("refused a policy that MUST parse (%s): %v", c.Why, err)
			case !c.Accept && err == nil:
				t.Errorf("accepted a policy that MUST be refused (%s)", c.Why)
			}
		})
	}
}

// The one rule the prose stated and the parser did not apply: §9.1 says fields
// are separated by "ASCII spaces and tabs **only**", and `strings.Fields`
// splits on every Unicode space -- so a vertical tab was a separator here and
// an error in the reference.
func TestOnlySpaceAndTabSeparateFields(t *testing.T) {
	good := "log k1 https://example/l\nwitness pi k2 https://example/w\nquorum pi\n"
	if _, err := Parse(good); err != nil {
		t.Fatalf("the control policy does not parse: %v", err)
	}
	// In the URL, which nothing else constrains. Putting it in the keyword
	// would be refused for not being a keyword, and the whitespace rule would
	// never be reached -- which is how the first version of this test passed
	// with the rule deleted.
	for _, ws := range []struct{ name, ch string }{
		{"vertical tab", "\v"}, {"form feed", "\f"}, {"carriage return", "\r"},
	} {
		t.Run(ws.name, func(t *testing.T) {
			bad := strings.Replace(good, "https://example/w", "https://example/"+ws.ch+"w", 1)
			if _, err := Parse(bad); err == nil {
				t.Errorf("a %s passed as ordinary content; §9.1 says any whitespace "+
					"other than space and tab is an error", ws.name)
			}
		})
	}
}

// --- Cold-model gate run 9, defect D7 -----------------------------------
//
// `policies/` tested one thing: does this text parse. Nothing in the suite
// ever took a policy and a set of cosigners and asked whether the quorum was
// met — so three readings that change what a quorum *means* all passed.
//
// `pol-dup-member-ok`: §9.1 says no member twice, and `group home 2 pi pi` is
// then satisfied by **one** witness. `pol-k-zero-ok`: §9.1 says `1 ≤ k ≤ n`,
// and `k = 0` is satisfied by **nobody**, so an uncosigned head passes.
// `pol-nested-group-flat`: §9.1 says a nested group counts as one member, and
// flattening it changes the arithmetic. The first two are parse rules with no
// negative; the third is an evaluation rule and parsing cannot reach it.

func TestEveryPolicyEvaluationCaseGetsTheStatedVerdict(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "policies", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name     string `json:"name"`
			Accept   bool   `json:"accept"`
			Evaluate []struct {
				Cosigners []string `json:"cosigners"`
				Satisfied bool     `json:"satisfied"`
				Why       string   `json:"why"`
			} `json:"evaluate"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	var evaluated int
	for _, c := range doc.Cases {
		if len(c.Evaluate) == 0 {
			continue
		}
		evaluated++
		body, err := os.ReadFile(filepath.Join(vectorRoot(), "policies", c.Name+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		rules, err := Parse(string(body))
		if err != nil {
			t.Fatalf("%s must parse before it can be evaluated: %v", c.Name, err)
		}
		for _, e := range c.Evaluate {
			t.Run(c.Name+"/"+strings.Join(e.Cosigners, "+"), func(t *testing.T) {
				if got := rules.Satisfied(e.Cosigners); got != e.Satisfied {
					t.Errorf("quorum satisfied = %v, want %v (%s)", got, e.Satisfied, e.Why)
				}
			})
		}
	}
	if evaluated == 0 {
		t.Error("no policy case carries an `evaluate` table, so the suite still only " +
			"tests whether a policy parses -- and what a quorum *means* is unpinned")
	}
}

// ...and the parse rules §9.1 states that had no negative at all.
func TestTheQuorumArithmeticRulesHaveNegatives(t *testing.T) {
	for _, want := range []string{
		"bad-duplicate-member", "bad-k-zero", "bad-k-leading-zero",
		"bad-carriage-return", "bad-uppercase-keyword",
	} {
		t.Run(want, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(vectorRoot(), "policies", want+".txt"))
			if err != nil {
				t.Fatalf("§9.1 states this rule and no vector reaches it: %v", err)
			}
			if _, err := Parse(string(body)); err == nil {
				t.Errorf("%s parsed; §9.1 says it must not", want)
			}
		})
	}
}
