package specdoc

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
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
		if !strings.Contains(text, name) {
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
