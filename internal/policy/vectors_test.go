package policy

import (
	"encoding/json"
	"github.com/onembyte/norn/internal/note"
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
	t.Run("distinct witness algorithm", func(t *testing.T) {
		text := policyText(t, "bad-witness-vkey-algorithm-distinct")
		if _, err := Parse(text); err == nil {
			t.Fatal("note-key witness accepted")
		}
		fields := strings.Fields(text)
		if len(fields) != 5 || fields[0] != "witness" {
			t.Fatal("expected one witness and one quorum, without log")
		}
		key, err := note.ParseVerifierKey(fields[2])
		if err != nil {
			t.Fatal(err)
		}
		repaired := strings.Replace(text, fields[2], note.CosignerVerifierKey(key.Name, key.Public), 1)
		if _, err := Parse(repaired); err != nil {
			t.Fatalf("algorithm repair: %v", err)
		}
	})
	t.Run("distinct log algorithm", func(t *testing.T) {
		text := policyText(t, "bad-log-vkey-algorithm-distinct")
		if _, err := Parse(text); err == nil {
			t.Fatal("cosignature log key accepted")
		}
		var logKey string
		seen := map[string]bool{}
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			at := 1
			if fields[0] == "witness" {
				at = 2
			} else if fields[0] != "log" {
				continue
			}
			key, err := note.ParseVerifierKey(fields[at])
			if err != nil {
				t.Fatal(err)
			}
			if seen[string(key.Public)] {
				t.Fatal("a duplicate public key masks the algorithm fault")
			}
			seen[string(key.Public)] = true
			if fields[0] == "log" {
				if key.Alg != note.AlgCosignature {
					t.Fatal("log key is not algorithm 0x04")
				}
				logKey = fields[at]
			}
		}
		if logKey == "" || len(seen) < 2 {
			t.Fatal("distinct log and witness keys are required")
		}
		key, err := note.ParseVerifierKey(logKey)
		if err != nil {
			t.Fatal(err)
		}
		repaired := strings.Replace(text, logKey, note.VerifierKey(key.Name, key.Public), 1)
		if _, err := Parse(repaired); err != nil {
			t.Fatalf("algorithm repair: %v", err)
		}
		t.Log("algorithm-only repair accepted")
	})
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
	good := policyText(t, "minimal")
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
			bad := strings.Replace(good, "https://log.norn.example/testnet",
				"https://log.norn.example/"+ws.ch+"testnet", 1)
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
	foundAll := false
	for _, c := range doc.Cases {
		if c.Name == "all-members" {
			foundAll = true
			if !c.Accept || len(c.Evaluate) != 3 {
				t.Fatal("all-members needs its three evaluation rows")
			}
			for i, want := range []string{"pi", "vps", "pi+vps"} {
				e := c.Evaluate[i]
				if strings.Join(e.Cosigners, "+") != want || e.Satisfied != (i == 2) || e.Why == "" {
					t.Fatal("all-members must refuse either singleton and accept both")
				}
			}
		}
		if len(c.Evaluate) == 0 {
			continue
		}
		evaluated++
		body, err := os.ReadFile(filepath.Join(vectorRoot(), "policies", c.Name+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		if c.Name == "all-members" && !strings.Contains(string(body), "group home all pi vps\nquorum home\n") {
			t.Fatal("all-members does not require both pi and vps")
		}
		rules, err := Parse(string(body))
		if err != nil {
			t.Fatalf("%s must parse before it can be evaluated: %v", c.Name, err)
		}
		for _, e := range c.Evaluate {
			t.Run(c.Name+"/"+strings.Join(e.Cosigners, "+"), func(t *testing.T) {
				if c.Name == "all-members" {
					t.Logf("cosigners %v: satisfied=%v", e.Cosigners, rules.Satisfied(e.Cosigners))
				}
				if got := rules.Satisfied(e.Cosigners); got != e.Satisfied {
					t.Errorf("quorum satisfied = %v, want %v (%s)", got, e.Satisfied, e.Why)
				}
			})
		}
	}
	if !foundAll {
		t.Error("missing multi-member all evaluation")
	}
	if evaluated == 0 {
		t.Error("no policy case carries an `evaluate` table, so the suite still only " +
			"tests whether a policy parses -- and what a quorum *means* is unpinned")
	}
}

// ...and the parse rules §9.1 states that had no negative at all.
func TestTheQuorumArithmeticRulesHaveNegatives(t *testing.T) {
	for _, want := range []string{
		"bad-duplicate-member", "bad-k-zero", "bad-k-leading-zero", "bad-k-above-size",
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
	if _, err := Parse(stripped); err != nil {
		t.Errorf("stripping from the `#` still does not parse (%v), so the vector "+
			"does not separate the comment readings", err)
	}
}

// --- Cold-model gate run 11, defects D2 and D12 -------------------------
//
// §9.1's `log lines` row argues that a Norn policy carries at most one `log`
// line "since a `log` line that is present must name `norn.trust.log_key` and
// **no key may appear twice in one policy**, a second one cannot be written".
// Both premises are rules; neither appears anywhere else in the document. The
// table they sit in is introduced as "the rest of the grammar, stated because
// a restatement that leaves it out is not enough to write an agreeing
// verifier" — and it left these out.
//
// Measured before fixing, the two implementations already disagreed:
//
//	same key under two names   Go refuses     · reference accepts
//	two `log` lines            Go accepts     · reference accepts   (nobody)
//	U+00A0 inside a URL        Go accepts     · reference refuses
//
// D-066 follows C2SP's byte rule: only tab and line feed are permitted ASCII
// controls. High-bit UTF-8 content, including Unicode whitespace, remains
// opaque content and never becomes a field separator.
//
// None of this is cosmetic. Policy text is carried verbatim in a `policy` log
// entry, which is `decode` unless it parses, so a policy one implementation
// refuses and the other accepts splits `state.json` — a byte-identical MUST —
// and with it every subsequent checkpoint's quorum.

func TestAKeyIsUsedOnceInAPolicy(t *testing.T) {
	const key = "norn-witness/pi+051d1c51+BHeagefoK0s3F5shdMl1Ahsd1ZCE9MC5F5gvM3cLTnZa"
	good := "witness a " + key + "\nquorum a\n"
	if _, err := Parse(good); err != nil {
		t.Fatalf("the control policy does not parse: %v", err)
	}
	// The same key under two names. `group home 2 a b` is then met by one
	// witness answering once, which is exactly what §9.1's `group` members row
	// exists to prevent — stated there for members and missing for keys.
	twice := "witness a " + key + "\nwitness b " + key + "\nquorum a\n"
	if _, err := Parse(twice); err == nil {
		t.Error("one key under two names was accepted; a quorum over `a` and `b` " +
			"is then met by a single witness")
	}
}

// D2, corrected. `c2sp.org/tlog-policy` says only that "multiple log lines
// with the same public key are not allowed" -- so several `log` lines with
// distinct keys are grammatical, and §9.1 promises the policy is that grammar
// "verbatim … not redefined here". An at-most-one rule shipped briefly in
// this repository (6.5l-iii) and was a redefinition; a parallel session got it
// right, and the two were reconciled. A Norn trust file still cannot carry a
// second `log` line -- the correspondence rule requires a present one to name
// `norn.trust.log_key` -- but that is the trust file's rule, not the grammar's.
func TestLogLinesFollowTheUpstreamGrammar(t *testing.T) {
	two := policyText(t, "two-log-lines")
	if _, err := Parse(two); err != nil {
		t.Errorf("two `log` lines with distinct keys were refused (%v); upstream "+
			"allows them and §9.1 says the grammar is not redefined here", err)
	}
	lines := strings.Split(two, "\n")
	lines[1] = lines[0]
	same := strings.Join(lines, "\n")
	if _, err := Parse(same); err == nil {
		t.Error("two `log` lines with the SAME key were accepted; that is the one " +
			"thing upstream rules out")
	}
}

func TestOnlyTabAndLineFeedAreAllowedASCIIControls(t *testing.T) {
	const key = "norn-witness/pi+051d1c51+BHeagefoK0s3F5shdMl1Ahsd1ZCE9MC5F5gvM3cLTnZa"
	line := func(mid string) string {
		return "witness a " + key + " https://example/" + mid + "w\nquorum a\n"
	}
	// Boundary and formerly-unvectored controls inside ordinary URL content.
	for _, c := range []struct{ name, ch string }{
		{"NUL", "\x00"}, {"backspace", "\x08"}, {"vertical tab", "\v"},
		{"form feed", "\f"}, {"carriage return", "\r"},
		{"unit separator", "\x1f"}, {"DEL", "\x7f"},
	} {
		if _, err := Parse(line(c.ch)); err == nil {
			t.Errorf("ASCII control %s passed; C2SP permits only tab and line feed", c.name)
		}
	}
	// High-bit content, including code points Unicode categorizes as spaces,
	// is opaque to the C2SP grammar and must not be split or rejected.
	for _, c := range []struct{ name, ch string }{
		{"non-breaking space", " "}, {"next-line", "\u0085"},
		{"en quad", " "}, {"ideographic space", "　"},
	} {
		if _, err := Parse(line(c.ch)); err != nil {
			t.Errorf("a %s was refused (%v); high-bit bytes are content, not "+
				"field separators", c.name, err)
		}
	}
}

// Nested groups may overlap in ways a single k-of-N intersection cannot
// describe, so the flat-group bound must not pretend to cover them.
func TestTheNestedFixtureHasNoFlatCollusionBound(t *testing.T) {
	p, err := Parse(policyText(t, "nested-group"))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := p.CollusionBound(); ok || got != 0 {
		t.Errorf("CollusionBound() = (%d, %v), want (0, false)", got, ok)
	}
}
