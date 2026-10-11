package docclaims

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

type observeBlock struct {
	line    int
	markers []string
	command string
}

// A marker belongs immediately before its fence, allowing blank lines. Keep
// every marker so a second one cannot silently replace the first.
func observeBlocks(t *testing.T, names ...string) []observeBlock {
	t.Helper()
	name := "OBSERVE.md"
	if len(names) != 0 {
		name = names[0]
	}
	lines := strings.Split(deploymentText(t, name), "\n")
	var blocks []observeBlock
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		fence := ""
		for _, prefix := range []string{"```", "~~~"} {
			if strings.HasPrefix(line, prefix) {
				fence = prefix
				break
			}
		}
		if fence == "" {
			continue
		}
		lang := strings.TrimSpace(strings.TrimPrefix(line, fence))
		switch lang {
		case "sh", "shell", "bash", "zsh", "console":
		default:
			t.Fatalf("%s:%d: command fence needs a shell language, got %q", name, i+1, lang)
		}
		block := observeBlock{line: i + 1}
		for j := i - 1; j >= 0; j-- {
			marker := strings.TrimSpace(lines[j])
			if marker == "" {
				continue
			}
			if !strings.HasPrefix(marker, "<!-- run:") {
				break
			}
			block.markers = append(block.markers, marker)
		}
		start := i + 1
		for i++; i < len(lines) && strings.TrimSpace(lines[i]) != fence; i++ {
		}
		if i == len(lines) {
			t.Fatalf("%s:%d: unclosed shell fence", name, block.line)
		}
		block.command = strings.Join(lines[start:i], "\n")
		blocks = append(blocks, block)
	}
	if len(blocks) == 0 {
		t.Fatalf("%s has no shell commands", name)
	}
	return blocks
}

func TestEveryObserveShellBlockNamesWhoRunsIt(t *testing.T) {
	for _, block := range observeBlocks(t) {
		if len(block.markers) != 1 || (block.markers[0] != "<!-- run: test -->" && block.markers[0] != "<!-- run: U1 -->") {
			t.Errorf("OBSERVE.md:%d: shell block needs exactly one test or U1 marker, got %q", block.line, block.markers)
		}
	}
}

// Execute the text itself, not a substitute command. Both the binary and a
// copy of the shipped vectors live in the temporary working directory.
func TestTheObserveTestCommandsRunOffline(t *testing.T) {
	blocks := observeBlocks(t)
	dir := t.TempDir()
	deploymentBinary(t, "norn", dir)
	if err := os.CopyFS(filepath.Join(dir, "testdata", "vectors"), os.DirFS(filepath.Join(root(t), "testdata", "vectors"))); err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, block := range blocks {
		if len(block.markers) != 1 || block.markers[0] != "<!-- run: test -->" {
			continue
		}
		ran++
		t.Run(strconv.Itoa(block.line), func(t *testing.T) {
			out := observeCommand(t, "OBSERVE.md", block, dir, 30*time.Second)
			if len(strings.TrimSpace(string(out))) == 0 {
				t.Errorf("OBSERVE.md:%d: verification printed nothing", block.line)
			}
		})
	}
	if ran == 0 {
		t.Fatal("OBSERVE.md has no test commands to run")
	}
}

// Like nornd's log-level guard, discover the uppercase kind constants from
// declarations. A new alarm must gain its own meaning and operator action.
func TestTheObserveAlarmsExplainEveryDeclaredKind(t *testing.T) {
	doc := deploymentText(t, "OBSERVE.md")
	_, alarms, ok := strings.Cut(doc, "## Alarms\n")
	if !ok {
		t.Fatal("OBSERVE.md has no alarms section")
	}
	alarms, _, _ = strings.Cut(alarms, "\n## ")
	rows := make(map[string]bool)
	for _, line := range strings.Split(alarms, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) == 5 && strings.TrimSpace(cells[2]) != "" && strings.TrimSpace(cells[3]) != "" {
			rows[strings.Trim(strings.TrimSpace(cells[1]), "`")] = true
		}
	}
	kindName := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	found := 0
	for _, pkg := range []string{"agent", "reconcile"} {
		files, err := filepath.Glob(filepath.Join(root(t), "internal", pkg, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range file.Decls {
				constants, ok := decl.(*ast.GenDecl)
				if !ok || constants.Tok != token.CONST {
					continue
				}
				for _, spec := range constants.Specs {
					for _, value := range spec.(*ast.ValueSpec).Values {
						literal, ok := value.(*ast.BasicLit)
						if !ok || literal.Kind != token.STRING {
							continue
						}
						kind, err := strconv.Unquote(literal.Value)
						if err != nil {
							t.Fatal(err)
						}
						if kindName.MatchString(kind) {
							found++
							if !rows[kind] {
								t.Errorf("OBSERVE.md alarms: %s needs a line with its meaning and action", kind)
							}
						}
					}
				}
			}
		}
	}
	if found == 0 {
		t.Fatal("no event or alarm kinds were enumerated")
	}
	for _, gap := range []string{"6.5l-ix-f-b-ii", "off Linux", "does not count a suspend", "younger than it is"} {
		if !strings.Contains(alarms, gap) {
			t.Errorf("OBSERVE.md alarms must name the suspend gap: missing %q", gap)
		}
	}
}

// Both guides execute their shell text through the same offline runner.
func observeCommand(t *testing.T, name string, block observeBlock, dir string, timeout time.Duration) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-eu", "-c", block.command)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s:%d: command failed: %v\n%s\n%s", name, block.line, err, block.command, out)
	}
	return out
}
