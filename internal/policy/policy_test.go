package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/trust"
)

const homelab = `# the homelab default: no single place and no single person
log     log+11111111+AAAA http://10.0.0.155:8099/norn
witness pi     pi+22222222+BBBB  http://10.0.0.153:8100
witness vps    vps+33333333+CCCC https://w.example.net
witness friend friend+44444444+DDDD https://bastion.example.net/x

group   home 2 pi vps friend
quorum  home
`

func mustParse(t *testing.T, text string) *Policy {
	t.Helper()
	p, err := Parse(text)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	return p
}

func TestTheHomelabPolicy(t *testing.T) {
	p := mustParse(t, homelab)

	if len(p.Logs) != 1 || p.Logs[0].URL != "http://10.0.0.155:8099/norn" {
		t.Errorf("logs = %+v", p.Logs)
	}
	if len(p.Witnesses) != 3 {
		t.Fatalf("witnesses = %+v", p.Witnesses)
	}
	if p.Quorum() != "home" || !p.RequiresCosignatures() {
		t.Errorf("quorum = %q", p.Quorum())
	}
	if strings.Join(p.WitnessNames(), ",") != "pi,vps,friend" {
		t.Errorf("names = %v", p.WitnessNames())
	}
}

// Two of three: the point of the homelab default is that no single physical
// place and no single person can reach the quorum alone.
func TestTwoOfThree(t *testing.T) {
	p := mustParse(t, homelab)

	cases := []struct {
		cosigners []string
		want      bool
	}{
		{nil, false},
		{[]string{"pi"}, false},
		{[]string{"pi", "vps"}, true},
		{[]string{"vps", "friend"}, true},
		{[]string{"pi", "vps", "friend"}, true},
		// A cosigner nobody named counts for nothing, however valid it is.
		{[]string{"pi", "stranger"}, false},
		{[]string{"stranger", "someone-else", "a-third"}, false},
		// Repeats are not extra witnesses.
		{[]string{"pi", "pi", "pi"}, false},
	}
	for _, c := range cases {
		if got := p.Satisfied(c.cosigners); got != c.want {
			t.Errorf("Satisfied(%v) = %v, want %v", c.cosigners, got, c.want)
		}
	}
}

func TestAllAnyAndNested(t *testing.T) {
	text := `witness a a+11111111+AAAA
witness b b+22222222+BBBB
witness c c+33333333+CCCC
group pair all a b
group either any b c
group both all pair either
quorum both
`
	p := mustParse(t, text)
	cases := []struct {
		cosigners []string
		want      bool
	}{
		{[]string{"a", "b"}, true},  // pair satisfied, either via b
		{[]string{"a", "c"}, false}, // pair needs b
		{[]string{"a", "b", "c"}, true},
		{[]string{"b", "c"}, false}, // pair needs a
	}
	for _, c := range cases {
		if got := p.Satisfied(c.cosigners); got != c.want {
			t.Errorf("Satisfied(%v) = %v, want %v", c.cosigners, got, c.want)
		}
	}
}

// `none` is a real option in the grammar, and a node that reads it should know
// it is running without corroboration -- not discover it from behaviour.
func TestQuorumNone(t *testing.T) {
	p := mustParse(t, "witness a a+11111111+AAAA\nquorum none\n")
	if p.RequiresCosignatures() {
		t.Error("quorum none still required cosignatures")
	}
	if !p.Satisfied(nil) {
		t.Error("quorum none was not satisfied by nothing")
	}
}

func TestCommentsAndBlankLinesAndWhitespace(t *testing.T) {
	text := "\n  # a comment\n\n\twitness  a   a+11111111+AAAA  \n  quorum a  \n\n"
	p := mustParse(t, text)
	if len(p.Witnesses) != 1 || p.Witnesses[0].Name != "a" {
		t.Errorf("witnesses = %+v", p.Witnesses)
	}
	if !p.Satisfied([]string{"a"}) {
		t.Error("a single witness quorum was not satisfied")
	}
}

// A policy is where a network says how much corroboration it wants, so a line
// nobody understood is a requirement nobody is enforcing.
func TestPoliciesThatMustBeRefused(t *testing.T) {
	cases := map[string]string{
		"no quorum line":         "witness a a+1+A\n",
		"two quorum lines":       "witness a a+1+A\nquorum a\nquorum a\n",
		"quorum names nothing":   "witness a a+1+A\nquorum ghost\n",
		"unknown keyword":        "witness a a+1+A\nkeeper b\nquorum a\n",
		"forward reference":      "group g 1 a\nwitness a a+1+A\nquorum g\n",
		"duplicate witness":      "witness a a+1+A\nwitness a a+2+B\nquorum a\n",
		"duplicate key":          "witness a k+1+A\nwitness b k+1+A\nquorum a\n",
		"group member twice":     "witness a a+1+A\ngroup g 1 a a\nquorum g\n",
		"threshold above size":   "witness a a+1+A\ngroup g 2 a\nquorum g\n",
		"threshold of zero":      "witness a a+1+A\ngroup g 0 a\nquorum g\n",
		"threshold not a number": "witness a a+1+A\ngroup g most a\nquorum g\n",
		"group with no members":  "witness a a+1+A\ngroup g 1\nquorum g\n",
		"witness with no key":    "witness a\nquorum a\n",
		"log with no key":        "log\nquorum none\n",
	}
	for why, text := range cases {
		t.Run(why, func(t *testing.T) {
			if _, err := Parse(text); err == nil {
				t.Errorf("accepted a policy with %s", why)
			}
		})
	}
}

// The shipped trust file's policy must be one this parser accepts, and its
// quorum must be reachable by the witnesses that file names -- otherwise the
// network could never accept a checkpoint at all.
func TestTheShippedPolicyIsUsable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(anchor.Policy)
	if err != nil {
		t.Fatalf("the shipped policy does not parse: %v", err)
	}

	var names []string
	for _, w := range anchor.Witnesses {
		names = append(names, w.Name)
	}
	if !p.Satisfied(names) {
		t.Error("the quorum cannot be met even by every witness the trust file names")
	}
	// And it must actually require more than one, or the homelab default's
	// whole point -- no single place, no single person -- is lost.
	if len(names) > 1 && p.Satisfied(names[:1]) {
		t.Error("one witness alone satisfies the shipped quorum")
	}
}
