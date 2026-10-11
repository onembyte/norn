package docclaims

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEveryTryNornShellBlockNamesWhoRunsIt(t *testing.T) {
	for _, block := range observeBlocks(t, "TRY-NORN.md") {
		if len(block.markers) != 1 || (block.markers[0] != "<!-- run: test -->" && block.markers[0] != "<!-- run: U1 -->") {
			t.Errorf("TRY-NORN.md:%d: shell block needs exactly one test or U1 marker, got %q", block.line, block.markers)
		}
	}
}

func TestTryNornNamesTheFourStagesInOrder(t *testing.T) {
	doc := deploymentText(t, "TRY-NORN.md")
	for _, stage := range []string{"## Build the binaries", "## Offline verification", "## The simulation", "## An observe-mode node"} {
		_, rest, ok := strings.Cut(doc, stage)
		if !ok {
			t.Fatalf("TRY-NORN.md needs %q in order", stage)
		}
		doc = rest
	}
	if !strings.Contains(readme(t), "| `TRY-NORN.md` |") {
		t.Error("README's document table must name TRY-NORN.md")
	}
}

// Run the page in order on a source copy, so its build really is the build
// the stranger runs. The simulator's results must stay outside that copy.
func TestTheTryNornTestCommandsRunOfflineAndPrintWhatTheyPromise(t *testing.T) {
	blocks := observeBlocks(t, "TRY-NORN.md")
	dir := t.TempDir()
	for _, name := range []string{"cmd", "internal", "testdata"} {
		if err := os.CopyFS(filepath.Join(dir, name), os.DirFS(filepath.Join(root(t), name))); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"go.mod", "go.sum", "Makefile", "SPEC.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(deploymentText(t, name)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	results := t.TempDir()
	t.Setenv("LAB_SIM_RESULTS", results)
	lines := strings.Split(deploymentText(t, "TRY-NORN.md"), "\n")
	expected := regexp.MustCompile("`([^`]+)`")
	ran := 0
	for i, block := range blocks {
		if len(block.markers) != 1 || block.markers[0] != "<!-- run: test -->" {
			continue
		}
		ran++
		t.Run(strconv.Itoa(block.line), func(t *testing.T) {
			start := time.Now()
			out := observeCommand(t, "TRY-NORN.md", block, dir, 2*time.Minute)
			t.Logf("TRY-NORN.md:%d completed in %s", block.line, time.Since(start))
			end := len(lines)
			if i+1 < len(blocks) {
				end = blocks[i+1].line - 1
			}
			claims := 0
			for _, line := range lines[block.line:end] {
				if !strings.HasPrefix(line, "Expect: ") {
					continue
				}
				for _, match := range expected.FindAllStringSubmatch(line, -1) {
					claims++
					if !strings.Contains(string(out), match[1]) {
						t.Errorf("TRY-NORN.md:%d: promised output %q is missing:\n%s", block.line, match[1], out)
					}
				}
			}
			if claims == 0 {
				t.Errorf("TRY-NORN.md:%d: test block needs an Expect: line with backticked output", block.line)
			}
		})
	}
	if ran < 5 {
		t.Fatalf("TRY-NORN.md needs tested build, log, bundle, evidence and simulation commands; ran %d blocks", ran)
	}
	for _, name := range []string{"norn", "nornd"} {
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || info.Mode()&0o111 == 0 {
			t.Errorf("the build did not produce executable %s: %v", name, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(results, "t7.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Latencies map[string]int64 `json:"latencies_ns"`
		Bound     int64            `json:"bound_ns"`
		TimeBasis string           `json:"time_basis"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Latencies) != 2 || result.Bound <= 0 || !strings.Contains(result.TimeBasis, "Simulated time") {
		t.Fatalf("t7.json did not record simulated eviction results: %+v", result)
	}
	for node, latency := range result.Latencies {
		if latency <= 0 || latency > result.Bound {
			t.Errorf("t7.json: %s latency %d exceeds bound %d", node, latency, result.Bound)
		}
	}
}
