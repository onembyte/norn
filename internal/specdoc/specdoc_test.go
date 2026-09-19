package specdoc

import (
	"os"
	"path/filepath"
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
