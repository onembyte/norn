package policy_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
	. "github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/trust"
)

func testVKey(name string, alg byte) string {
	seed := sha256.Sum256([]byte("norn/policy-test/" + name))
	private := ed25519.NewKeyFromSeed(seed[:])
	return note.VerifierKeyFor(name, private.Public().(ed25519.PublicKey), alg)
}

var homelab = fmt.Sprintf(`# the homelab default: no single place and no single person
log     %s http://10.0.0.155:8099/norn
witness pi     %s  http://10.0.0.153:8100
witness vps    %s https://w.example.net
witness friend %s https://bastion.example.net/x

group   home 2 pi vps friend
quorum  home
`, testVKey("norn/log", note.AlgEd25519), testVKey("norn-witness/pi", note.AlgCosignature),
	testVKey("norn-witness/vps", note.AlgCosignature), testVKey("norn-witness/friend", note.AlgCosignature))

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
	text := fmt.Sprintf(`witness a %s
witness b %s
witness c %s
group pair all a b
group either any b c
group both all pair either
quorum both
`, testVKey("a", note.AlgCosignature), testVKey("b", note.AlgCosignature),
		testVKey("c", note.AlgCosignature))
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
	p := mustParse(t, "quorum none\n")
	if p.RequiresCosignatures() {
		t.Error("quorum none still required cosignatures")
	}
	if !p.Satisfied(nil) {
		t.Error("quorum none was not satisfied by nothing")
	}
}

func TestCommentsAndBlankLinesAndWhitespace(t *testing.T) {
	text := fmt.Sprintf("\n  # a comment\n\n\twitness  a   %s  \n  quorum a  \n\n",
		testVKey("a", note.AlgCosignature))
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
	keyA := testVKey("a", note.AlgCosignature)
	keyB := testVKey("b", note.AlgCosignature)
	cases := map[string]string{
		"no quorum line":         fmt.Sprintf("witness a %s\n", keyA),
		"two quorum lines":       fmt.Sprintf("witness a %s\nquorum a\nquorum a\n", keyA),
		"quorum names nothing":   fmt.Sprintf("witness a %s\nquorum ghost\n", keyA),
		"unknown keyword":        fmt.Sprintf("witness a %s\nkeeper b\nquorum a\n", keyA),
		"forward reference":      fmt.Sprintf("group g 1 a\nwitness a %s\nquorum g\n", keyA),
		"duplicate witness":      fmt.Sprintf("witness a %s\nwitness a %s\nquorum a\n", keyA, keyB),
		"duplicate key":          fmt.Sprintf("witness a %s\nwitness b %s\nquorum a\n", keyA, keyA),
		"group member twice":     fmt.Sprintf("witness a %s\ngroup g 1 a a\nquorum g\n", keyA),
		"threshold above size":   fmt.Sprintf("witness a %s\ngroup g 2 a\nquorum g\n", keyA),
		"threshold of zero":      fmt.Sprintf("witness a %s\ngroup g 0 a\nquorum g\n", keyA),
		"threshold not a number": fmt.Sprintf("witness a %s\ngroup g most a\nquorum g\n", keyA),
		"group with no members":  fmt.Sprintf("witness a %s\ngroup g 1\nquorum g\n", keyA),
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

// Quorum size is not the collusion bound: a forking log needs only the
// witnesses shared by two otherwise honest quorums to sign both branches.
func TestTheCollusionBoundCountsTheSmallestQuorumIntersection(t *testing.T) {
	for _, c := range []struct {
		k, n, want int
	}{
		{2, 3, 1}, {3, 3, 3}, {1, 2, 0}, {2, 4, 0},
	} {
		t.Run(fmt.Sprintf("%d-of-%d", c.k, c.n), func(t *testing.T) {
			var text strings.Builder
			var members []string
			for i := 0; i < c.n; i++ {
				name := fmt.Sprintf("w%d", i)
				fmt.Fprintf(&text, "witness %s %s\n", name, testVKey(name, note.AlgCosignature))
				members = append(members, name)
			}
			// An unused witness does not enlarge the quorum's member set.
			fmt.Fprintf(&text, "witness unused %s\n", testVKey("unused", note.AlgCosignature))
			fmt.Fprintf(&text, "group g %d %s\nquorum g\n", c.k, strings.Join(members, " "))
			p := mustParse(t, text.String())
			if got, ok := p.CollusionBound(); !ok || got != c.want {
				t.Errorf("CollusionBound() = (%d, %v), want (%d, true)", got, ok, c.want)
			}
		})
	}
	for _, text := range []string{
		"quorum none\n",
		fmt.Sprintf("witness a %s\nquorum a\n", testVKey("a", note.AlgCosignature)),
	} {
		if got, ok := mustParse(t, text).CollusionBound(); ok || got != 0 {
			t.Errorf("CollusionBound() = (%d, %v) for a quorum without a group", got, ok)
		}
	}
}
