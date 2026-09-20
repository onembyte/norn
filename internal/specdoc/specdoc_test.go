package specdoc

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SPEC.md is a normative document edited by hand and by script. These checks
// exist because two normative sections were silently deleted by regex splices
// (§14 in checkpoint 0.2, the canonical-JSON rules in 0.7d) and neither was
// caught by the test suite or by a conformance run, since neither section has
// test vectors. Structure is cheap to verify; do it on every build.

func load(t *testing.T) *Doc {
	t.Helper()
	path := filepath.Join("..", "..", "SPEC.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	doc, err := Parse(string(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return doc
}

// RequiredSections is the manifest: sections the implementation or another
// document depends on by number. Deleting one must break the build.
var RequiredSections = map[string]string{
	"4":    "Entries",
	"4.0":  "Encoding profile",
	"4.2":  "Signature preimage",
	"5":    "Replay",
	"5.1":  "Procedure",
	"5.2":  "Reason codes",
	"5.3":  "Canonical state schema",
	"7":    "Submission and receipts",
	"9":    "Trust file",
	"9.1":  "CBOR fields",
	"9.3":  "Fingerprint",
	"12":   "Test vectors",
	"12.1": "Coverage",
	"14":   "Canonical JSON",
}

func TestTopLevelNumbersAreContiguous(t *testing.T) {
	if gaps := load(t).NumberGaps(); len(gaps) > 0 {
		t.Errorf("missing or out-of-order top-level sections: %v", gaps)
	}
}

func TestSubsectionNumbersAreContiguous(t *testing.T) {
	for _, bad := range load(t).SubsectionGaps() {
		t.Errorf("subsection numbering broken: %s", bad)
	}
}

func TestNoDuplicateSectionNumbers(t *testing.T) {
	for _, dup := range load(t).Duplicates() {
		t.Errorf("duplicate section number: %s", dup)
	}
}

func TestRequiredSectionsArePresent(t *testing.T) {
	doc := load(t)
	for number, want := range RequiredSections {
		sec, ok := doc.Section(number)
		if !ok {
			t.Errorf("§%s (%s) is missing from SPEC.md", number, want)
			continue
		}
		if !sec.TitleContains(want) {
			t.Errorf("§%s title is %q, expected it to mention %q", number, sec.Title, want)
		}
	}
}

func TestEveryCrossReferenceResolves(t *testing.T) {
	for _, ref := range load(t).DanglingRefs() {
		t.Errorf("§%s is referenced from line %d but does not exist", ref.Number, ref.Line)
	}
}

func TestSectionsAreNotEmpty(t *testing.T) {
	doc := load(t)
	for _, sec := range doc.Sections {
		if sec.Body == "" && !doc.HasChildren(sec.Number) {
			t.Errorf("§%s (%s) has no body", sec.Number, sec.Title)
		}
	}
}

func TestParserFindsSectionsAndBodies(t *testing.T) {
	doc, err := Parse("## 1. First\n\nbody one\n\n### 1.1 Nested\n\nbody two\n\n## 2. Second\n\nbody three\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Sections) != 3 {
		t.Fatalf("expected 3 sections, got %d", len(doc.Sections))
	}
	sec, ok := doc.Section("1.1")
	if !ok || sec.Title != "Nested" || sec.Body != "body two" {
		t.Errorf("unexpected §1.1: %+v", sec)
	}
	if gaps := doc.NumberGaps(); len(gaps) != 0 {
		t.Errorf("unexpected gaps: %v", gaps)
	}
}

func TestDetectsAMissingSection(t *testing.T) {
	doc, err := Parse("## 1. A\n\nx\n\n## 3. C\n\ny\n")
	if err != nil {
		t.Fatal(err)
	}
	if gaps := doc.NumberGaps(); len(gaps) != 1 || gaps[0] != 2 {
		t.Errorf("expected §2 reported missing, got %v", gaps)
	}
}

func TestDetectsADanglingReference(t *testing.T) {
	doc, err := Parse("## 1. A\n\nsee §9 for details\n")
	if err != nil {
		t.Fatal(err)
	}
	refs := doc.DanglingRefs()
	if len(refs) != 1 || refs[0].Number != "9" {
		t.Errorf("expected §9 reported dangling, got %+v", refs)
	}
}

func TestReferencesIntoOtherDocumentsAreIgnored(t *testing.T) {
	doc, err := Parse("## 1. A\n\nSee RFC 6962 §2.1 and RFC 8949 §4.2.1, but also §1.\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Refs) != 1 || doc.Refs[0].Number != "1" {
		t.Errorf("expected only the internal §1 reference, got %+v", doc.Refs)
	}
}

// A frozen specification does not contain promises.
//
// Every one of these markers was true when it was written and stopped being
// true without anybody noticing: §10 carried `NOT YET IMPLEMENTED — Phase 4`
// for eight checkpoints after the quorum check landed, and §13's open item
// said "pending a decision" for just as long after the decision was made. A
// reader implementing from a frozen spec cannot tell a live caveat from a
// stale one, so a frozen spec must not contain either.
//
// The exception is prose that *describes* deferral as history rather than as a
// present state -- "closed by", "was owed" -- which reads as a record and not
// as an instruction.
func TestAFrozenSpecMakesNoPromises(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Status: **v1**") {
		t.Skip("the spec is still a draft; this guard applies once it is frozen")
	}

	for _, marker := range []string{
		"NOT YET IMPLEMENTED", "pending a decision", "TODO", "TBD",
		"to be decided", "owed by | Phase",
		// §8.1 carried "Reconcile before freezing v1" *through* the freeze,
		// because this list did not name the one phrase it used. A guard is
		// only as good as its vocabulary.
		"before freezing", "Reconcile before", "has not been checked",
		"not yet claimed", "Not yet claimed",
	} {
		if idx := strings.Index(string(raw), marker); idx >= 0 {
			line := 1 + strings.Count(string(raw[:idx]), "\n")
			t.Errorf("SPEC.md:%d still says %q. A frozen spec cannot carry a "+
				"promise: a reader has no way to tell a live caveat from one that "+
				"stopped being true.", line, marker)
		}
	}
}

// The vector suite is the cross-implementation contract, and its README is the
// first thing a second implementer reads. A file nobody described is a file
// nobody can use -- and the README has already been wrong once: it claimed the
// whole directory came from the Python reference, after `served/`, `proofs/`
// and `fork/` started coming from Go and `anchors/` from
// `python-opentimestamps`.
//
// So: every top-level entry is named in the README, and nothing is named that
// is not there.
func TestEveryVectorIsDescribed(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(readme)

	found, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range found {
		name := item.Name()
		if name == "README.md" {
			continue
		}
		if !citedAsPath(text, name) {
			t.Errorf("testdata/vectors/%s is not described in the suite's README. A "+
				"file a second implementer cannot identify is one they cannot use.",
				name)
		}
	}
}

// And the suite says where every byte came from. "Two provenances, stated
// plainly" is SPEC §12's own promise, and it is now three: the Python
// reference, this project's Go, and `python-opentimestamps`. A reader deciding
// how much a vector proves has to know which.
func TestTheSuiteStatesItsProvenances(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"contrib/norn-ref", "norn-genlog", "python-opentimestamps"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the README does not say that %s produces part of this suite", want)
		}
	}
}

// `SHA256SUMS` is for somebody who downloaded this directory and does not have
// the generators: it is how they know they have the set the specification
// describes, whole and unmodified.
//
// Inside this repository it does a second job. `make vectors-check`
// regenerates and diffs, which catches a vector that drifted from its
// generator; this catches one edited by hand in a way that happens to survive
// regeneration -- and it fails with the filename, which a diff of ninety files
// does not.
func TestTheVectorChecksumsAreCurrent(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "SHA256SUMS"))
	if err != nil {
		t.Fatalf("the suite ships no checksums: %v", err)
	}

	listed := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("not a sha256sum line: %q", line)
		}
		listed[name] = sum
	}

	var counted int
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "SHA256SUMS" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		want, ok := listed[rel]
		if !ok {
			t.Errorf("%s is not in SHA256SUMS; run `make vectors-sums`", rel)
			return nil
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(body)); got != want {
			t.Errorf("%s has changed since the checksums were written (%s, listed %s)",
				rel, got[:12], want[:12])
		}
		counted++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if counted != len(listed) {
		t.Errorf("SHA256SUMS lists %d files, %d are present; run `make vectors-sums`",
			len(listed), counted)
	}
}

// --- Cold-model gate run 5, defects G1 and G5 (6.5a) ---------------------
//
// Run 5's implementer built a `tlog-policy` parser strictly from this document
// and it rejected the suite's own `trust.cbor`. The grammar is somebody else's,
// the document requires a normative parse against it, and it was not in the
// list of specifications this one reuses. These tests make both halves of that
// failure impossible to reintroduce.

func rawSpec(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatalf("read SPEC.md: %v", err)
	}
	return string(raw)
}

var reC2SP = regexp.MustCompile(`c2sp\.org/[a-z0-9-]+`)

// A normative parse against a grammar the document does not list is a grammar
// the second implementer has to guess.
func TestEveryReusedSpecificationIsListed(t *testing.T) {
	spec := rawSpec(t)

	// The head list: the bullets that name what this document reuses.
	declared := map[string]bool{}
	for _, line := range strings.Split(spec, "\n") {
		if !strings.HasPrefix(line, "- `c2sp.org/") {
			continue
		}
		if m := reC2SP.FindString(line); m != "" {
			declared[m] = true
		}
	}
	if len(declared) < 4 {
		t.Fatalf("found %d declared C2SP references; the head list is not being read", len(declared))
	}

	for _, used := range reC2SP.FindAllString(spec, -1) {
		if !declared[used] {
			t.Errorf("%s is required by the body but is not in the list of specifications this document reuses", used)
		}
	}
}

// §9.2 renders the trust file as TOML. Hashes and keys may be elided there --
// they carry no grammar. The policy string carries nothing *but* grammar, and
// eliding it is what cost run 5 its first attempt.
func TestTheRenderedPolicyIsTheShippedPolicy(t *testing.T) {
	shipped, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "trust.toml"))
	if err != nil {
		t.Fatalf("read trust.toml: %v", err)
	}
	want := policyLine(string(shipped))
	if want == "" {
		t.Fatal("the shipped trust.toml has no policy line")
	}
	got := policyLine(rawSpec(t))
	if got == "" {
		t.Fatal("SPEC.md renders no policy line")
	}
	if got != want {
		t.Errorf("the policy §9.2 shows is not the one the suite ships.\n  spec:    %s\n  shipped: %s", got, want)
	}
}

func policyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "policy") && strings.Contains(line, "=") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// G5: two clocks were specified for one decision -- "the checkpoint time" in
// §5.3 and `now` in §10 -- and the document defined neither, though a
// tlog-checkpoint body carries no timestamp at all. This is the rule that
// decides when a device stops being admitted to the VPN.
func TestTheEvaluationClockIsDefinedAndUsedOnce(t *testing.T) {
	spec := rawSpec(t)

	if strings.Contains(spec, "expired(now)") {
		t.Error("§10 still judges expiry against the local wall clock; A11 says that clock is untrusted")
	}

	doc := load(t)
	for _, section := range []string{"5.3", "10"} {
		sec, ok := doc.Section(section)
		if !ok {
			t.Fatalf("§%s is missing", section)
		}
		if !strings.Contains(strings.ToLower(sec.Body), "evaluation time") {
			t.Errorf("§%s decides expiry without naming the evaluation time", section)
		}
	}

	// Defined as a derivation from something the artifact actually carries.
	if !strings.Contains(strings.ToLower(spec), "quorum time") {
		t.Error("the evaluation time is never derived from the cosignature timestamps, which are the only timestamps there are")
	}
}

// --- Cold-model gate run 5, defect G7 ------------------------------------
//
// §12.1 opens by saying a suite that looks complete is worse than one that
// admits its holes, "and an inaccurate coverage claim is the same failure
// wearing a different hat". Measured against the shipped files it was wrong in
// six places: a count of nine where twelve ship, and four rows naming
// negatives that existed only as Go tests. §12's file table also omitted three
// directories outright.
//
// The table is the thing this specification asks to be judged on, so it is now
// judged by the build, in both directions.

func vectorsDir() string { return filepath.Join("..", "..", "testdata", "vectors") }

// coverage is §12 and §12.1 together: the file table and the claims about it.
func coverage(t *testing.T) string {
	t.Helper()
	doc := load(t)
	var b strings.Builder
	for _, number := range []string{"12", "12.1"} {
		section, ok := doc.Section(number)
		if !ok {
			t.Fatalf("§%s is missing", number)
		}
		b.WriteString(section.Body)
		b.WriteString("\n")
	}
	return b.String()
}

var reTicked = regexp.MustCompile("`([^`]+)`")

// Every path the coverage table spells out has to be there. Four rows named
// negatives that shipped as no files at all, which a reader discovers only by
// looking for them.
func TestEveryVectorPathTheSpecCitesExists(t *testing.T) {
	// Extensions the suite uses; a citation may omit one.
	suffixes := []string{"", ".cbor", ".checkpoint", ".txt", ".json", ".note", ".ots", ".toml"}

	// Only paths rooted in the suite. `transparency-dev/formats` is a library
	// this project checks itself against, not a vector, and a checker that
	// cannot tell the difference invents work.
	top := map[string]bool{}
	entries, err := os.ReadDir(vectorsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		top[e.Name()] = true
	}

	for _, m := range reTicked.FindAllStringSubmatch(coverage(t), -1) {
		cited := strings.TrimSpace(strings.TrimSuffix(m[1], "/"))
		// Templates describe a shape, not a file.
		if strings.ContainsAny(cited, "<>… ") || !strings.Contains(cited, "/") {
			continue
		}
		if first, _, _ := strings.Cut(cited, "/"); !top[first] {
			continue
		}
		found := false
		for _, suffix := range suffixes {
			if _, err := os.Stat(filepath.Join(vectorsDir(), cited+suffix)); err == nil {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("§12 cites %q, which does not ship. A coverage claim for a file "+
				"nobody receives is the failure §12.1 opens by warning about.", cited)
		}
	}
}

// And the other direction: something in the suite that the table never mentions
// is coverage nobody can find.
func TestEveryVectorDirectoryIsInTheCoverageTable(t *testing.T) {
	text := coverage(t)
	found, err := os.ReadDir(vectorsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range found {
		name := item.Name()
		if name == "README.md" {
			continue
		}
		if !citedAsPath(text, name) {
			t.Errorf("testdata/vectors/%s is not cited as a path anywhere in §12 or §12.1", name)
		}
	}
}

// §12.1's closing line and the header's line 10 cannot both be true.
func TestTheSpecDoesNotClaimTotalCoverage(t *testing.T) {
	if strings.Contains(rawSpec(t), "Everything normative is vectored") {
		t.Error("§12.1 claims every normative rule is vectored; the header says it does " +
			"not claim that, and the header is the one that is true")
	}
}

// citedAsPath reports whether the text names this vector as a path rather than
// merely containing its letters. `proven` is also an ordinary English word, and
// a check that accepted it anywhere would call the directory described because
// the prose says "proven set" two hundred lines away.
func citedAsPath(text, name string) bool {
	for _, m := range reTicked.FindAllStringSubmatch(text, -1) {
		cited := strings.TrimSpace(m[1])
		if cited == name {
			return true
		}
		for _, sep := range []string{"/", "."} {
			if strings.HasPrefix(cited, name+sep) {
				return true
			}
		}
	}
	return false
}
