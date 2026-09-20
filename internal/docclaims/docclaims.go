// Package docclaims checks the claims this project's own prose makes about
// itself against the repository those claims describe.
//
// A specification is checked by its vectors and a plan by its gates. README.md
// had nothing checking it, and so it went on saying "planning complete, not
// yet code" through six phases of work. PUBLICATION.md sent reviewers to a
// path that was never created and told them to run a make target that does not
// exist. The claims worth making about a project are checkable ones, and
// checkable claims can be verified on every build.
package docclaims

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Claims are the countable statements README.md makes about this repository.
type Claims struct {
	Packages    int
	Tests       int
	GatesTicked int
	GatesTotal  int
}

var (
	// Markdown wraps, and emphasis markers land in the middle of a phrase.
	// A README author should not have to avoid a line break to stay checked.
	rePackages = regexp.MustCompile(`([0-9]+)[\s*_]+Go[\s*_]+packages`)
	reTests    = regexp.MustCompile(`([0-9]+)[\s*_]+tests`)
	reGates    = regexp.MustCompile(`([0-9]+)[\s*_]+of[\s*_]+([0-9]+)[\s*_]+gate[\s*_]+lines`)
)

// ParseClaims reads the numbers the README states about itself. A README that
// states none is an error rather than a vacuous pass: the check exists because
// silence is how the old one drifted.
func ParseClaims(md string) (Claims, error) {
	var c Claims
	var err error
	if c.Packages, err = count(rePackages, md, "N Go packages"); err != nil {
		return Claims{}, err
	}
	if c.Tests, err = count(reTests, md, "N tests"); err != nil {
		return Claims{}, err
	}
	m := reGates.FindStringSubmatch(md)
	if m == nil {
		return Claims{}, fmt.Errorf("README states no gate progress (want %q)", "N of M gate lines")
	}
	if c.GatesTicked, err = strconv.Atoi(m[1]); err != nil {
		return Claims{}, err
	}
	if c.GatesTotal, err = strconv.Atoi(m[2]); err != nil {
		return Claims{}, err
	}
	return c, nil
}

func count(re *regexp.Regexp, md, want string) (int, error) {
	m := re.FindStringSubmatch(md)
	if m == nil {
		return 0, fmt.Errorf("README makes no %q claim", want)
	}
	return strconv.Atoi(m[1])
}

// A Transcript is one command the README shows, with the output lines it
// promises the reader will see.
type Transcript struct {
	Command string
	Expect  []string
}

// Transcripts returns the console blocks of the README in order. A line
// beginning "$ " starts a command; the lines under it are its output. An
// elision ("...") promises nothing and is skipped.
func Transcripts(md string) []Transcript {
	var out []Transcript
	for _, block := range fences(md, "console") {
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "$ "):
				out = append(out, Transcript{Command: strings.TrimSpace(line[2:])})
			case len(out) == 0, strings.TrimSpace(line) == "",
				strings.TrimSpace(line) == "...", strings.HasPrefix(strings.TrimSpace(line), "#"):
				continue
			default:
				last := &out[len(out)-1]
				last.Expect = append(last.Expect, strings.TrimRight(line, " \t"))
			}
		}
	}
	return out
}

// Commands is the list a reader would type, in order.
func Commands(md string) []string {
	blocks := Transcripts(md)
	cmds := make([]string, 0, len(blocks))
	for _, b := range blocks {
		cmds = append(cmds, b.Command)
	}
	return cmds
}

func fences(md, lang string) []string {
	var out []string
	var cur *strings.Builder
	for _, line := range strings.Split(md, "\n") {
		switch {
		case cur == nil && strings.TrimSpace(line) == "```"+lang:
			cur = &strings.Builder{}
		case cur != nil && strings.HasPrefix(strings.TrimSpace(line), "```"):
			out = append(out, cur.String())
			cur = nil
		case cur != nil:
			cur.WriteString(line + "\n")
		}
	}
	return out
}

var reGate = regexp.MustCompile(`(?m)^- \[([ xX])\] `)

// Gates counts the gate checkboxes in PLAN.md: how many are ticked, and how
// many there are.
func Gates(plan string) (ticked, total int) {
	for _, m := range reGate.FindAllStringSubmatch(plan, -1) {
		total++
		if m[1] != " " {
			ticked++
		}
	}
	return ticked, total
}

// Measure counts the Go packages and test functions under root, the two
// numbers the README quotes. A package is a directory holding Go source;
// testdata is fixtures, not code, and is not counted.
func Measure(root string) (packages, tests int, err error) {
	dirs := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "testdata" || (strings.HasPrefix(name, ".") && path != root) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		dirs[filepath.Dir(path)] = true
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		tests += len(reTestFunc.FindAllString(string(raw), -1))
		return nil
	})
	return len(dirs), tests, err
}

var reTestFunc = regexp.MustCompile(`(?m)^func Test[A-Za-z0-9_]*\(`)
