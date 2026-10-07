package docclaims

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// README.md is the one document a stranger reads first and the one nobody
// re-reads. For two days it said "planning complete, not yet code" while the
// repository grew 48 packages and 598 tests. No test noticed, because no test
// read it. These do: every countable claim the README makes is checked against
// the thing it describes, and every command it invites a reader to run is run.

func root(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..")
}

func readme(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root(t), "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	return string(raw)
}

func plan(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root(t), "PLAN.md"))
	if err != nil {
		t.Fatalf("read PLAN.md: %v", err)
	}
	return string(raw)
}

// The failure that prompted this package: prose that quietly stopped being true.
func TestTheREADMEsCountsAreCurrent(t *testing.T) {
	claims, err := ParseClaims(readme(t))
	if err != nil {
		t.Fatalf("the README must state what it is made of: %v", err)
	}

	pkgs, tests, err := Measure(root(t))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Packages != pkgs {
		t.Errorf("README says %d Go packages, the tree has %d", claims.Packages, pkgs)
	}
	if claims.Tests != tests {
		t.Errorf("README says %d tests, the tree has %d", claims.Tests, tests)
	}
}

// "Never mark a gate PASS with partial credit" is the project's rule for
// PLAN.md. The README is where breaking it would actually mislead somebody.
func TestTheGateClaimMatchesThePlan(t *testing.T) {
	claims, err := ParseClaims(readme(t))
	if err != nil {
		t.Fatal(err)
	}
	ticked, total := Gates(plan(t))
	if claims.GatesTicked != ticked || claims.GatesTotal != total {
		t.Errorf("README claims %d of %d gate lines; PLAN.md has %d of %d",
			claims.GatesTicked, claims.GatesTotal, ticked, total)
	}
	if ticked == total {
		t.Skip("every gate is ticked; the honesty check below has nothing to catch")
	}
	// With gates still open the README must not read as if the thing is proven.
	for _, overclaim := range []string{"production-ready", "battle-tested", "proven in production"} {
		if strings.Contains(strings.ToLower(readme(t)), overclaim) {
			t.Errorf("README says %q while %d gate lines are open", overclaim, total-ticked)
		}
	}
}

// A standing instruction, and the honest answer: 32 bytes of one, optionally,
// as an advisory anchor. Putting it in the pitch would misdescribe the project.
func TestTheTaglineNeverSaysBlockchain(t *testing.T) {
	md := readme(t)
	end := strings.Index(md, "## ")
	if end < 0 {
		t.Fatal("README has no sections")
	}
	if strings.Contains(strings.ToLower(md[:end]), "blockchain") {
		t.Error("the pitch must not sell a blockchain; Norn is a log")
	}
}

// The checkpoint's own scope, asserted rather than assumed.
func TestTheREADMEAnswersTheQuestionsItPromised(t *testing.T) {
	md := strings.ToLower(readme(t))
	for _, want := range []string{
		"## what norn is",
		"## who this is not for",
		"## threat model",
		"## how norn compares",
		"## try it",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("README is missing the %q section", want)
		}
	}
}

// A comparison that names no rival is marketing.
func TestTheComparisonNamesItsRivals(t *testing.T) {
	md := readme(t)
	for _, rival := range []string{"Tailnet Lock", "Nebula", "NetBird"} {
		if !strings.Contains(md, rival) {
			t.Errorf("the comparison table never mentions %s", rival)
		}
	}
}

// The commands in the README are a promise to a stranger with a fresh clone.
// Keeping that promise is cheap to check and embarrassing to break.
func TestTheQuickstartCommandsRun(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	cmds := Commands(readme(t))
	if len(cmds) == 0 {
		t.Fatal("the README invites the reader to run nothing")
	}

	bin := filepath.Join(t.TempDir(), "norn")
	build := exec.Command("go", "build", "-o", bin, "./cmd/norn")
	build.Dir = root(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	var ran int
	for _, line := range cmds {
		fields := strings.Fields(line)
		switch {
		case fields[0] == "go" && len(fields) > 1 && fields[1] == "build":
			// Performed above, into a temp dir; running it here would write
			// a binary into the working tree.
			continue
		case fields[0] == "go" && len(fields) > 1 && fields[1] == "test":
			// Running the suite from inside the suite does not terminate.
			continue
		case fields[0] != "./norn":
			t.Errorf("quickstart runs something this test cannot vouch for: %q", line)
			continue
		}
		t.Run(strings.Join(fields[1:3], " "), func(t *testing.T) {
			cmd := exec.Command(bin, fields[1:]...)
			cmd.Dir = root(t)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s\nfailed: %v\n%s", line, err, out)
			}
			if len(strings.TrimSpace(string(out))) == 0 {
				t.Errorf("%s printed nothing", line)
			}
		})
		ran++
	}
	if ran == 0 {
		t.Error("no README command was actually executed")
	}
}

// The README shows output as well as commands. Output that has drifted is
// worse than none: it teaches the reader to expect the wrong thing.
func TestThePromisedOutputStillAppears(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := filepath.Join(t.TempDir(), "norn")
	build := exec.Command("go", "build", "-o", bin, "./cmd/norn")
	build.Dir = root(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	for _, block := range Transcripts(readme(t)) {
		if !strings.HasPrefix(block.Command, "./norn") {
			continue
		}
		fields := strings.Fields(block.Command)
		cmd := exec.Command(bin, fields[1:]...)
		cmd.Dir = root(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", block.Command, err, out)
		}
		got := string(out)
		for _, line := range block.Expect {
			if !strings.Contains(got, line) {
				t.Errorf("%s no longer prints %q\ngot:\n%s", block.Command, line, got)
			}
		}
	}
}

func TestParsing(t *testing.T) {
	md := "# Norn\n\n" +
		"*48 Go packages, 598 tests. 14 of 38 gate lines are ticked.*\n\n" +
		"## Try it\n\n" +
		"```console\n" +
		"$ go build -o norn ./cmd/norn\n" +
		"$ ./norn verify -log testdata/vectors/served\n" +
		"size       90 entries\n" +
		"```\n"

	claims, err := ParseClaims(md)
	if err != nil {
		t.Fatal(err)
	}
	want := Claims{Packages: 48, Tests: 598, GatesTicked: 14, GatesTotal: 38}
	if claims != want {
		t.Errorf("ParseClaims = %+v, want %+v", claims, want)
	}

	cmds := Commands(md)
	if len(cmds) != 2 || cmds[1] != "./norn verify -log testdata/vectors/served" {
		t.Errorf("Commands = %q", cmds)
	}

	blocks := Transcripts(md)
	if len(blocks) != 2 {
		t.Fatalf("Transcripts = %d blocks, want 2", len(blocks))
	}
	if got := blocks[1].Expect; len(got) != 1 || got[0] != "size       90 entries" {
		t.Errorf("expected output = %q", got)
	}
	if blocks[0].Expect != nil {
		t.Errorf("a command with no output should expect none, got %q", blocks[0].Expect)
	}
}

// Emphasis and a line break must not hide a claim from its check.
func TestClaimsSurviveMarkdownWrapping(t *testing.T) {
	md := "*49 Go packages, 609 tests. **14 of 38\ngate lines** are ticked.*"
	got, err := ParseClaims(md)
	if err != nil {
		t.Fatal(err)
	}
	want := Claims{Packages: 49, Tests: 609, GatesTicked: 14, GatesTotal: 38}
	if got != want {
		t.Errorf("ParseClaims = %+v, want %+v", got, want)
	}
}

func TestParsingRefusesAREADMEThatClaimsNothing(t *testing.T) {
	if _, err := ParseClaims("# Norn\n\nA thing.\n"); err == nil {
		t.Error("a README with no countable claim should be a failure, not a pass")
	}
}

func TestGatesCounts(t *testing.T) {
	ticked, total := Gates("- [x] one\n- [ ] two\n- [X] three\nnot a gate\n- [ ] four\n")
	if ticked != 2 || total != 4 {
		t.Errorf("Gates = %d of %d, want 2 of 4", ticked, total)
	}
}

func TestMeasureCountsThisPackage(t *testing.T) {
	pkgs, tests, err := Measure(root(t))
	if err != nil {
		t.Fatal(err)
	}
	if pkgs < 1 || tests < 1 {
		t.Fatalf("Measure found %d packages and %d tests", pkgs, tests)
	}
	// testdata holds fixtures, some of them deliberately malformed Go.
	if _, _, err := Measure(filepath.Join(root(t), "testdata")); err != nil {
		t.Errorf("Measure should tolerate a tree with no Go in it: %v", err)
	}
}

// --- D-060 -------------------------------------------------------------
//
// `GOSSIP.md` carries the operational state machine, so it has to agree with
// §8.1 about which state wins when both hold. Before D-060 it drew `degraded`
// as `S < age ≤ S_hard`, which silently assumes `S_hard > S`, and repeated the
// config floor's old justification — that a limit below the network's
// `staleness` "would drop every peer before the network had even called the
// view degraded". Under D-060 that configuration is legitimate and is the
// point of a local floor.

func TestTheGossipStateMachineAgreesWithD060(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "GOSSIP.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	if strings.Contains(doc, "before the network had even called the view degraded") {
		t.Error("GOSSIP.md still gives the pre-D-060 reason for the hard_stale " +
			"floor. A hard limit tighter than the network's `staleness` is now " +
			"legitimate — it is what makes S_hard a limit the roots cannot raise")
	}
	if !strings.Contains(doc, "S_hard is tighter than S") {
		t.Error("GOSSIP.md's state machine does not say what happens when a " +
			"node's own limit is tighter than the network's, which is the case " +
			"D-060 is about: `degraded` is empty and the node goes from fresh " +
			"straight to hard-stale")
	}
}

// A parallel session reached the opposite answer on D1 and its paragraph
// auto-merged into GOSSIP.md right under the D-060 one, textually clean and
// saying "such a node stays `fresh` up to `S`". Two phrase checks above were
// both green with the contradiction on the page. This one looks for the
// losing reading itself.
func TestTheGossipStateMachineDoesNotAlsoStateTheRejectedOrder(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "GOSSIP.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, rejected := range []string{
		"stays `fresh` up to `S`",
		"never drops peers\nwhile the network calls its view fresh",
		"It never drops peers",
	} {
		if strings.Contains(string(raw), rejected) {
			t.Errorf("GOSSIP.md states the fresh-first reading D-060 rejected (%q). "+
				"A document that gives both orders gives neither", rejected)
		}
	}
}

// D-064 demoted the three companions to informative and d-xii moved every rule
// they used to own into `SPEC.md`. A document's standing is only real where
// the document itself says so: a companion that never names the spec invites a
// reader to treat its narrative as a contract, which is the drift d-xii spent
// five checkpoints undoing. Each one has to carry the label and name its
// better — neither alone is a declaration.
func TestTheCompanionsSayWhatTheyAre(t *testing.T) {
	for _, name := range []string{"GOSSIP.md", "ENFORCEMENT.md", "ENROLLMENT.md"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		// Flattened, because prose wraps: a self-declaration split across a
		// line break is still a self-declaration.
		doc := strings.Join(strings.Fields(string(raw)), " ")
		if !strings.Contains(doc, "informative") {
			t.Errorf("%s never says it is informative", name)
		}
		if !strings.Contains(doc, "disagrees with `SPEC.md`") {
			t.Errorf("%s never says which document wins when it disagrees with "+
				"`SPEC.md`", name)
		}
		// A companion may say where the normative text lives — "(normative in
		// `SPEC.md` §…)" — but may not claim any of its own text normative:
		// the header just said the whole document is informative, and a
		// section that contradicts its own header is how the drift starts
		// again. ENFORCEMENT.md §4 carried exactly that heading ("normative
		// pseudocode") until d-xii-v.
		for at := 0; ; at++ {
			i := strings.Index(doc[at:], "(normative")
			if i < 0 {
				break
			}
			at += i
			if !strings.HasPrefix(doc[at+len("(normative"):], " in `SPEC.md`") {
				t.Errorf("%s claims normative text of its own (%q): an "+
					"informative document may only point at where the "+
					"normative text lives", name, doc[at:at+40])
			}
		}
	}
}
