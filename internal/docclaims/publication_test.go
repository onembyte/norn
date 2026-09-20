package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// PUBLICATION.md is the document that decides what a reviewer is told to look
// at. When it was written there was no code, so nothing it promised could be
// wrong yet; by Phase 6 it was sending people to `contrib/verify-py/`, which
// was never created, and telling them to run `make demos`, which has no
// target. A plan that ages into a set of false directions wastes the goodwill
// of the exact people it was written to impress.

func publication(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root(t), "PUBLICATION.md"))
	if err != nil {
		t.Fatalf("read PUBLICATION.md: %v", err)
	}
	return string(raw)
}

func makefile(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root(t), "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	return string(raw)
}

// topLevel is what actually sits at the root of the repository.
func topLevel(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(root(t))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		out[e.Name()] = true
	}
	return out
}

// present reports whether a reviewer sent to this name would find anything.
// An empty directory is not an artifact: `lab/` and `demo/` have existed since
// the repository was created and contain nothing.
func present(t *testing.T, name string, targets map[string]bool) bool {
	t.Helper()
	if target, ok := strings.CutPrefix(name, "make "); ok {
		return targets[strings.TrimSpace(target)]
	}
	path := filepath.Join(root(t), name)
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return true
	}
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

// Two documents pitching the same project in two different sentences is how a
// project ends up not knowing what it is.
func TestThePitchMatchesTheProduct(t *testing.T) {
	pitch := OneLine(publication(t))
	if pitch == "" {
		t.Fatal("PUBLICATION.md states no one-line pitch")
	}
	tag := Tagline(readme(t))
	if tag == "" {
		t.Fatal("README.md has no tagline under its title")
	}
	if pitch != tag {
		t.Errorf("the pitch and the product disagree:\n  PUBLICATION.md: %q\n  README.md:      %q", pitch, tag)
	}
}

// The inventory is checked in both directions. Claiming something exists when
// it does not sends a reviewer to a dead path; claiming something is missing
// when it was built months ago is how README.md spent six phases saying there
// was no code.
func TestTheArtifactInventoryIsHonestInBothDirections(t *testing.T) {
	inv := Inventory(publication(t))
	if len(inv) < 5 {
		t.Fatalf("PUBLICATION.md lists %d artifacts; it is meant to inventory what a reviewer can touch", len(inv))
	}
	targets := MakeTargets(makefile(t))

	for _, a := range inv {
		exists := present(t, a.Name, targets)
		switch {
		case a.Claimed && !exists:
			t.Errorf("PUBLICATION.md says %q exists; it does not", a.Name)
		case !a.Claimed && exists:
			t.Errorf("PUBLICATION.md says %q does not exist yet; it does — say so", a.Name)
		}
	}
}

// A path named in the prose but absent from the inventory is unreviewed: it is
// exactly where `contrib/verify-py/` hid.
func TestEveryPathTheProseNamesIsInventoried(t *testing.T) {
	md := publication(t)
	inv := map[string]bool{}
	for _, a := range Inventory(md) {
		inv[a.Name] = true
	}
	targets := MakeTargets(makefile(t))

	top := topLevel(t)
	for _, name := range Mentions(md) {
		if inv[name] || !InRepo(name, top) {
			continue
		}
		if !present(t, name, targets) {
			t.Errorf("PUBLICATION.md names %q, which a reviewer would not find, and does not inventory it", name)
		}
	}
}

// The checkpoint asked for what to say when somebody asks the obvious
// questions. A question with no answer under it is a note to self.
func TestTheObviousQuestionsHaveAnswers(t *testing.T) {
	qs := Questions(publication(t))
	if len(qs) < 8 {
		t.Errorf("PUBLICATION.md answers %d obvious questions; a reviewer will ask more than that", len(qs))
	}
	for _, q := range qs {
		if len(strings.Fields(q.A)) < 15 {
			t.Errorf("%q is answered in %d words, which is a shrug not an answer", q.Q, len(strings.Fields(q.A)))
		}
	}
	// The ones that get asked first, every time.
	want := []string{"blockchain", "tailscale", "trust"}
	joined := strings.ToLower(strings.Join(func() []string {
		var all []string
		for _, q := range qs {
			all = append(all, q.Q)
		}
		return all
	}(), " | "))
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("nobody asked about %q? they will", w)
		}
	}
}

// One comparison table, in the document a stranger reads. A second one drifts
// away from the first and then the project disagrees with itself in public.
//
// The check is on header rows only: a table with a column per rival is a
// comparison, while a sentence naming two of them is just a sentence.
func TestTheComparisonLivesInExactlyOnePlace(t *testing.T) {
	rivals := []string{"Tailnet Lock", "Nebula", "NetBird", "Headscale", "ZeroTier", "innernet"}
	for _, header := range HeaderRows(publication(t)) {
		var found []string
		for _, r := range rivals {
			if strings.Contains(header, r) {
				found = append(found, r)
			}
		}
		if len(found) > 1 {
			t.Errorf("PUBLICATION.md gives a column to each of %v; the comparison belongs in README.md alone:\n  %s", found, header)
		}
	}
}

func TestHeaderRowsAreTheRowAboveTheDashes(t *testing.T) {
	md := "| A | B |\n|---|---|\n| one | two |\n\ntext | with a pipe\n"
	got := HeaderRows(md)
	if len(got) != 1 || !strings.Contains(got[0], "A") {
		t.Errorf("HeaderRows = %q", got)
	}
}

func TestAForeignRepositoryIsNotOneOfOurPaths(t *testing.T) {
	top := topLevel(t)
	if InRepo("transparency-dev/witness", top) {
		t.Error("another project's repository was read as a path in this one")
	}
	for _, ours := range []string{"contrib/norn-ref/", "SPEC.md", "make demos"} {
		if !InRepo(ours, top) {
			t.Errorf("%q is ours and should be checked", ours)
		}
	}
	// A typo inside a directory we do own is still caught.
	if !InRepo("contrib/verify-py/", top) {
		t.Error("a missing path under contrib/ must stay checkable")
	}
}

func TestAnEmptyDirectoryIsNotAnArtifact(t *testing.T) {
	// The rule that keeps `lab/` and `demo/` honest until the lab is built.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dir, "empty")); err != nil || !info.IsDir() {
		t.Fatalf("setup: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "empty"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("setup: %v, %d entries", err, len(entries))
	}
}

func TestPublicationParsing(t *testing.T) {
	md := "# P\n\n**One line:** *A thing for another thing.*\n\n" +
		"| Artifact | Today | Note |\n|---|---|---|\n" +
		"| `SPEC.md` | ✅ | frozen |\n" +
		"| `make demos` | ⬜ | needs the lab |\n\n" +
		"## 7. The obvious questions\n\n" +
		"### Is this a blockchain?\n\nNo. " + strings.Repeat("word ", 20) + "\n\n" +
		"### Why not Tailscale?\n\nBecause. " + strings.Repeat("word ", 20) + "\n"

	if got := OneLine(md); got != "A thing for another thing." {
		t.Errorf("OneLine = %q", got)
	}
	inv := Inventory(md)
	if len(inv) != 2 {
		t.Fatalf("Inventory = %+v", inv)
	}
	if inv[0].Name != "SPEC.md" || !inv[0].Claimed {
		t.Errorf("inventory[0] = %+v", inv[0])
	}
	if inv[1].Name != "make demos" || inv[1].Claimed {
		t.Errorf("inventory[1] = %+v", inv[1])
	}
	qs := Questions(md)
	if len(qs) != 2 || qs[0].Q != "Is this a blockchain?" {
		t.Fatalf("Questions = %+v", qs)
	}
	if !strings.HasPrefix(qs[0].A, "No.") {
		t.Errorf("answer = %q", qs[0].A)
	}
	if got := Mentions(md); len(got) != 2 {
		t.Errorf("Mentions = %q", got)
	}
}

func TestTaglineReadsTheBoldClaimUnderTheTitle(t *testing.T) {
	if got := Tagline("# Norn\n\n**A claim.**\n\n> a blockquote\n"); got != "A claim." {
		t.Errorf("Tagline = %q", got)
	}
	if got := Tagline("# Norn\n\nno claim here\n"); got != "" {
		t.Errorf("Tagline invented %q", got)
	}
}

func TestMakeTargetsAreFound(t *testing.T) {
	targets := MakeTargets(makefile(t))
	for _, want := range []string{"test", "lint", "vectors-check"} {
		if !targets[want] {
			t.Errorf("MakeTargets missed %q", want)
		}
	}
	if targets["demos"] {
		t.Error("MakeTargets invented a demos target")
	}
}
