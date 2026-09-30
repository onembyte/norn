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

// --- Cold-model gate run 10, defects D9 and D10 -------------------------
//
// §9.1's most emphatic rule — "ASCII space and tab **only**, in runs. Any
// other whitespace character anywhere in a line is an **error**" — was pinned
// by no vector at all. `V112_AnyWhitespaceSep`, the reading the sentence
// forbids in bold, passed all 236 checks: both whitespace negatives put the
// stray character inside an optional URL, so a reader that treats it as a
// separator sees a five-field `witness` line and refuses it for **arity** —
// a rule §9.1 never stated.
//
// One unstated rule was standing in for another, which is the worst shape a
// specification can have: delete the rule the vector is named after and the
// vector stays green.

// policyText reads one grammar vector verbatim. The bytes are the case — some
// of these turn on a trailing newline, or on a character `strings.TrimSpace`
// would take away.
func policyText(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(vectorRoot(), "policies", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// D9. A whitespace negative earns its name only if the stray character is the
// *only* thing wrong with it — so putting an ASCII space there instead must
// leave a policy that parses. That is the whole test: if the substitution does
// not parse, some other rule is doing the refusing and a reader may drop the
// whitespace rule entirely without the suite noticing.
func TestAWhitespaceNegativeIsRefusedForItsWhitespaceAndNothingElse(t *testing.T) {
	for _, c := range []struct{ name, ch string }{
		{"bad-vertical-tab", "\v"},
		{"bad-form-feed", "\f"},
		{"bad-carriage-return", "\r"},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := policyText(t, c.name)
			if !strings.Contains(text, c.ch) {
				t.Fatalf("%s carries no %q", c.name, c.ch)
			}
			if _, err := Parse(text); err == nil {
				t.Fatal("the vector must be refused")
			}
			// The reading §9.1 forbids: treat it as a separator like any other
			// whitespace. A conforming reader refuses this text; a reader
			// holding `V112_AnyWhitespaceSep` sees exactly what follows.
			asSeparator := strings.ReplaceAll(text, c.ch, " ")
			if _, err := Parse(asSeparator); err != nil {
				t.Errorf("reading %q as a separator gives a policy this parser refuses "+
					"anyway (%v), so the vector pins that rule instead and the "+
					"whitespace rule can be deleted without the suite noticing", c.ch, err)
			}
		})
	}
}

// Cold-model gate run 11, D12. The test above rules out one lax reading and
// not the other. Between `quorum` and `pi`, a reader that keeps the character
// as ordinary CONTENT sees one field, an unknown keyword, and refuses for that
// -- so with all three characters demoted to content, every vector named after
// them stayed green. Only a unit test in this package noticed, and a second
// implementer does not receive it.
//
// So each character ships again inside a URL, where the content reading
// parses. Swapping it for an ordinary letter is that reading exactly; if the
// swapped text does not parse, something other than the character is being
// refused, and the vector pins nothing.
func TestAWhitespaceNegativeIsNotContentEither(t *testing.T) {
	for _, c := range []struct{ name, ch string }{
		{"bad-vertical-tab-in-url", "\v"},
		{"bad-form-feed-in-url", "\f"},
		{"bad-carriage-return-in-url", "\r"},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := policyText(t, c.name)
			if strings.Count(text, c.ch) != 1 {
				t.Fatalf("%s must carry exactly one %q", c.name, c.ch)
			}
			if _, err := Parse(text); err == nil {
				t.Fatal("the vector must be refused")
			}
			asContent := strings.ReplaceAll(text, c.ch, "x")
			if _, err := Parse(asContent); err != nil {
				t.Errorf("reading %q as content gives a policy this parser refuses "+
					"anyway (%v), so the vector does not separate an error from "+
					"content", c.ch, err)
			}
			// And the placement must not be one where a split parses: that
			// reading belongs to the other test, and a vector answering both
			// would be answering neither cleanly.
			if _, err := Parse(strings.ReplaceAll(text, c.ch, " ")); err == nil {
				t.Errorf("reading %q as a separator parses too; place it in a field "+
					"a split would break", c.ch)
			}
		})
	}
}

// D9's other half. Arity is what was silently doing the work, so it has to be
// stated and given its own negative — otherwise the fix moves the unstated
// rule rather than removing it.
func TestADirectiveWithTooManyFieldsIsRefused(t *testing.T) {
	text := policyText(t, "bad-extra-field")
	if _, err := Parse(text); err == nil {
		t.Error("a `quorum` line with two names was accepted; §9.1 bounds each " +
			"directive's field count")
	}
	// ...and the line is otherwise exactly a valid one, so nothing else can be
	// refusing it.
	fields := strings.Fields(text)
	if len(fields) == 0 {
		t.Fatal("empty vector")
	}
	trimmed := strings.Replace(text, "quorum pi extra\n", "quorum pi\n", 1)
	if _, err := Parse(trimmed); err != nil {
		t.Errorf("dropping the extra field leaves a policy this parser still refuses "+
			"(%v), so the vector is not about arity", err)
	}
}

// D10. "A line whose first non-space character is `#` is ignored" left three
// readings alive, each passing 236/236: only U+0020 counts as the indent, so a
// tab-indented comment is a directive; strip from the first `#` anywhere,
// which turns a trailing `#` into a comment; and both at once, which needs no
// leading-`#` rule at all. Two vectors separate all three.
func TestTheCommentRuleIsPinnedInBothDirections(t *testing.T) {
	// A tab-indented comment MUST be ignored. A reader for whom only a space
	// counts sees the keyword `#` and refuses the file.
	tabbed := policyText(t, "comment-tab-indented")
	if !strings.Contains(tabbed, "\t#") {
		t.Fatal("comment-tab-indented carries no tab-indented comment")
	}
	if _, err := Parse(tabbed); err != nil {
		t.Errorf("a tab-indented comment was not ignored: %v", err)
	}

	// A `#` after the fields is an ordinary character, so the line has one
	// field too many and the file is refused. A reader that strips from the
	// first `#` sees `quorum pi` and accepts it.
	trailing := policyText(t, "bad-trailing-comment")
	if _, err := Parse(trailing); err == nil {
		t.Error("a `#` after a directive's fields was treated as a comment; §9.1 " +
			"ignores a `#` line, not a `#` tail")
	}
	// And stripping from the `#` is exactly what makes it parse, which is what
	// makes this vector the one that separates the two readings.
	stripped := ""
	for _, line := range strings.Split(trailing, "\n") {
		if at := strings.Index(line, "#"); at >= 0 {
			line = strings.TrimRight(line[:at], " \t")
		}
		stripped += line + "\n"
	}
	if _, err := Parse(strings.TrimSuffix(stripped, "\n")); err != nil {
		t.Errorf("stripping from the `#` still does not parse (%v), so the vector "+
			"does not separate the comment readings", err)
	}
}
