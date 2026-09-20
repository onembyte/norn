package docclaims

import (
	"regexp"
	"strings"
)

// A project's outward-facing prose makes three kinds of checkable claim: what
// it says the project is, what it says the project contains, and what it says
// in answer to the questions it expects. All three are here.

var reOneLine = regexp.MustCompile(`(?m)^\*\*One line:\*\*\s*(.+)$`)

// OneLine returns the pitch PUBLICATION.md leads with, stripped of emphasis so
// it can be compared with the same sentence set in a different document.
func OneLine(md string) string {
	m := reOneLine.FindStringSubmatch(md)
	if m == nil {
		return ""
	}
	return unemphasise(m[1])
}

var reTagline = regexp.MustCompile(`(?m)^\*\*(.+)\*\*$`)

// Tagline returns the bold claim under a README's title: the first thing a
// stranger reads, and the sentence the rest of the project must agree with.
func Tagline(md string) string {
	m := reTagline.FindStringSubmatch(md)
	if m == nil {
		return ""
	}
	return unemphasise(m[1])
}

func unemphasise(s string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(s), "*_"))
}

// An Artifact is one thing a reviewer could go and touch, and whether the
// document says it is there today.
type Artifact struct {
	Name    string // a repo path, or "make <target>"
	Claimed bool   // the document says this exists now
	Note    string
}

var reRow = regexp.MustCompile("^\\|\\s*`([^`]+)`\\s*\\|\\s*(✅|⬜)\\s*\\|(.*)$")

// Inventory reads the table of what exists today. Both marks are meaningful:
// ✅ is a promise that a reviewer will find it, ⬜ a promise that they will not.
func Inventory(md string) []Artifact {
	var out []Artifact
	for _, line := range strings.Split(md, "\n") {
		m := reRow.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		out = append(out, Artifact{
			Name:    strings.TrimSpace(m[1]),
			Claimed: m[2] == "✅",
			Note:    strings.TrimSpace(strings.Trim(m[3], "|")),
		})
	}
	return out
}

// A Question is one a reviewer asks in the first five minutes, with the answer
// the project intends to give.
type Question struct {
	Q string
	A string
}

// Questions reads the `###` headings that end in a question mark, each with
// the prose underneath it.
func Questions(md string) []Question {
	var out []Question
	var body *strings.Builder
	flush := func() {
		if body != nil {
			out[len(out)-1].A = strings.TrimSpace(body.String())
		}
		body = nil
	}
	for _, line := range strings.Split(md, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "### "):
			flush()
			q := strings.TrimSpace(strings.TrimPrefix(trimmed, "### "))
			if !strings.HasSuffix(q, "?") {
				continue
			}
			out = append(out, Question{Q: q})
			body = &strings.Builder{}
		case strings.HasPrefix(trimmed, "#"):
			flush()
		case body != nil:
			body.WriteString(line + "\n")
		}
	}
	flush()
	return out
}

var reTicked = regexp.MustCompile("`([^`]+)`")

// Mentions lists the repository paths and make targets the prose names, so
// that every one of them can be checked. A URL is not a path, and a word with
// a dot in it is not necessarily a file; only things that look like somewhere
// a reviewer would actually go are returned.
func Mentions(md string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reTicked.FindAllStringSubmatch(md, -1) {
		name := strings.TrimSpace(m[1])
		if seen[name] || !looksLikePath(name) {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

var fileSuffix = []string{".md", ".go", ".py", ".sh", ".cbor", ".json", ".yml", ".yaml"}

func looksLikePath(s string) bool {
	if strings.HasPrefix(s, "make ") {
		return len(strings.Fields(s)) == 2
	}
	if strings.Contains(s, "://") || strings.Contains(s, ".com") || strings.Contains(s, " ") {
		return false
	}
	for _, suf := range fileSuffix {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return strings.Contains(s, "/")
}

var reTarget = regexp.MustCompile(`(?m)^([a-zA-Z0-9_-]+):`)

// MakeTargets is the set of targets the Makefile actually defines.
func MakeTargets(mk string) map[string]bool {
	out := map[string]bool{}
	for _, m := range reTarget.FindAllStringSubmatch(mk, -1) {
		out[m[1]] = true
	}
	return out
}

var reDashes = regexp.MustCompile(`^\|[\s:|-]+\|$`)

// HeaderRows returns each markdown table's header line: the row immediately
// above the `|---|` separator. A table that gives a column to each of several
// products is a comparison; a sentence that names two of them is not.
func HeaderRows(md string) []string {
	lines := strings.Split(md, "\n")
	var out []string
	for i, line := range lines {
		if i == 0 || !reDashes.MatchString(strings.TrimSpace(line)) {
			continue
		}
		if prev := strings.TrimSpace(lines[i-1]); strings.HasPrefix(prev, "|") {
			out = append(out, prev)
		}
	}
	return out
}

// InRepo reports whether a mention points into this repository rather than at
// somebody else's, given the repository's top-level entries. `contrib/norn-ref/`
// is ours and must be findable; `transparency-dev/witness` is a project we
// depend on and is not a path at all.
func InRepo(name string, topLevel map[string]bool) bool {
	if strings.HasPrefix(name, "make ") {
		return true
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(name, "./"), "/")
	return topLevel[first]
}
