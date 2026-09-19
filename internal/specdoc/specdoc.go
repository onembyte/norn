// Package specdoc parses the structure of SPEC.md so that the build can refuse
// a spec whose sections have gone missing, been renumbered, or are referenced
// but absent.
//
// It deliberately understands only structure — headings and "§N" references —
// and has no opinion about the protocol. Semantics are the conformance
// vectors' job; this catches the class of damage vectors cannot see, because a
// section with no vectors can be deleted without any test noticing.
package specdoc

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Section is one numbered heading and the text beneath it, up to the next
// heading of any level.
type Section struct {
	Number string // "5" or "5.3"
	Title  string // heading text with the number stripped
	Line   int    // 1-based line of the heading
	Body   string // trimmed text under the heading
}

// TitleContains reports whether the title mentions want, case-insensitively.
func (s Section) TitleContains(want string) bool {
	return strings.Contains(strings.ToLower(s.Title), strings.ToLower(want))
}

// Ref is a "§N" cross-reference found in the prose.
type Ref struct {
	Number string
	Line   int
}

// Doc is the parsed structure of a specification document.
type Doc struct {
	Sections []Section
	Refs     []Ref

	byNumber map[string]Section
}

var (
	headingRE = regexp.MustCompile(`^(#{2,3})\s+(\d+(?:\.\d+)?)\.?\s+(.*)$`)
	// A "§N" reference, with whatever precedes it on the line, so that
	// references into *other* documents ("RFC 6962 §2.1") can be excluded.
	refRE    = regexp.MustCompile(`(.{0,16})§(\d+(?:\.\d+)*)`)
	externRE = regexp.MustCompile(`(?i)(RFC\s*\d+|draft-[a-z0-9-]+)\s*$`)
)

// Parse reads a Markdown specification and records its numbered sections and
// cross-references.
func Parse(text string) (*Doc, error) {
	doc := &Doc{byNumber: map[string]Section{}}
	lines := strings.Split(text, "\n")

	type pending struct {
		sec   Section
		start int
	}
	var open *pending
	closeOpen := func(end int) {
		if open == nil {
			return
		}
		open.sec.Body = strings.TrimSpace(strings.Join(lines[open.start:end], "\n"))
		doc.Sections = append(doc.Sections, open.sec)
		open = nil
	}

	for i, line := range lines {
		if m := headingRE.FindStringSubmatch(line); m != nil {
			closeOpen(i)
			open = &pending{
				sec:   Section{Number: m[2], Title: strings.TrimSpace(m[3]), Line: i + 1},
				start: i + 1,
			}
			continue
		}
		for _, r := range refRE.FindAllStringSubmatch(line, -1) {
			if externRE.MatchString(r[1]) {
				continue // a section of another document, e.g. "RFC 6962 §2.1"
			}
			doc.Refs = append(doc.Refs, Ref{Number: r[2], Line: i + 1})
		}
	}
	closeOpen(len(lines))

	for _, s := range doc.Sections {
		doc.byNumber[s.Number] = s
	}
	if len(doc.Sections) == 0 {
		return nil, fmt.Errorf("no numbered sections found")
	}
	return doc, nil
}

// Section looks up a section by its number.
func (d *Doc) Section(number string) (Section, bool) {
	s, ok := d.byNumber[number]
	return s, ok
}

func (d *Doc) topLevel() []int {
	var out []int
	seen := map[int]bool{}
	for _, s := range d.Sections {
		if strings.Contains(s.Number, ".") {
			continue
		}
		n, err := strconv.Atoi(s.Number)
		if err != nil || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// NumberGaps returns the top-level section numbers that are absent between the
// lowest and highest present.
func (d *Doc) NumberGaps() []int {
	nums := d.topLevel()
	if len(nums) == 0 {
		return nil
	}
	present := map[int]bool{}
	for _, n := range nums {
		present[n] = true
	}
	var gaps []int
	for n := nums[0]; n <= nums[len(nums)-1]; n++ {
		if !present[n] {
			gaps = append(gaps, n)
		}
	}
	return gaps
}

// SubsectionGaps reports parents whose subsections skip a number. Numbering may
// start at .0 or .1; anything after that must be consecutive.
func (d *Doc) SubsectionGaps() []string {
	kids := map[string][]int{}
	for _, s := range d.Sections {
		parent, child, found := strings.Cut(s.Number, ".")
		if !found {
			continue
		}
		n, err := strconv.Atoi(child)
		if err != nil {
			continue
		}
		kids[parent] = append(kids[parent], n)
	}
	var out []string
	for parent, ns := range kids {
		sort.Ints(ns)
		for i := 1; i < len(ns); i++ {
			if ns[i] != ns[i-1]+1 {
				out = append(out, fmt.Sprintf("§%s jumps from .%d to .%d", parent, ns[i-1], ns[i]))
			}
		}
	}
	sort.Strings(out)
	return out
}

// Duplicates returns section numbers that appear on more than one heading.
func (d *Doc) Duplicates() []string {
	count := map[string]int{}
	for _, s := range d.Sections {
		count[s.Number]++
	}
	var out []string
	for number, n := range count {
		if n > 1 {
			out = append(out, fmt.Sprintf("§%s appears %d times", number, n))
		}
	}
	sort.Strings(out)
	return out
}

// HasChildren reports whether any subsection of this number exists, in which
// case the parent heading is allowed to carry no body of its own.
func (d *Doc) HasChildren(number string) bool {
	prefix := number + "."
	for _, s := range d.Sections {
		if strings.HasPrefix(s.Number, prefix) {
			return true
		}
	}
	return false
}

// DanglingRefs returns cross-references that point at no section.
func (d *Doc) DanglingRefs() []Ref {
	var out []Ref
	seen := map[string]bool{}
	for _, r := range d.Refs {
		if _, ok := d.byNumber[r.Number]; ok || seen[r.Number] {
			continue
		}
		seen[r.Number] = true
		out = append(out, r)
	}
	return out
}
