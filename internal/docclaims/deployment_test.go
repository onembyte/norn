package docclaims

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func deploymentText(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root(t), name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func deploymentBinary(t *testing.T, name, dir string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", path, "./cmd/"+name)
	cmd.Dir = root(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, out)
	}
	return path
}

type dockerDirective struct{ instruction, value string }

// Keep repeated directives and join continuations: either can undo a
// restriction that looked correct on the first physical line.
func dockerStages(t *testing.T, text string) [][]dockerDirective {
	t.Helper()
	var stages [][]dockerDirective
	var pending string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pending += line
		if strings.HasSuffix(pending, "\\") {
			pending = strings.TrimSuffix(pending, "\\") + " "
			continue
		}
		instruction, value, ok := strings.Cut(pending, " ")
		if !ok {
			t.Fatalf("not a Dockerfile directive: %q", pending)
		}
		instruction, value = strings.ToUpper(instruction), strings.TrimSpace(value)
		pending = ""
		if instruction == "FROM" {
			stages = append(stages, nil)
		}
		if len(stages) == 0 {
			t.Fatal("a directive precedes the first stage")
		}
		stages[len(stages)-1] = append(stages[len(stages)-1], dockerDirective{instruction, value})
	}
	if pending != "" {
		t.Fatal("unfinished Dockerfile continuation")
	}
	return stages
}

// The container is written here, not built. Check its deployment contract
// without a daemon, and obtain the flags from the actual binary's flag set.
func TestTheLogContainerBuildsStaticAndRunsWithoutRoot(t *testing.T) {
	stages := dockerStages(t, deploymentText(t, "contrib/norn-log/Dockerfile"))
	if len(stages) < 2 {
		t.Fatal("the log container needs a builder and a runtime stage")
	}
	mod := deploymentText(t, "go.mod")
	version := regexp.MustCompile(`(?m)^toolchain go(\S+)$`).FindStringSubmatch(mod)
	if version == nil {
		version = regexp.MustCompile(`(?m)^go (\S+)$`).FindStringSubmatch(mod)
	}
	if version == nil {
		t.Fatal("go.mod names no Go version")
	}
	static := false
	for _, stage := range stages {
		for _, directive := range stage {
			fields := strings.Fields(directive.value)
			if directive.instruction == "FROM" {
				if len(fields) == 0 || !strings.Contains(fields[0], ":") || strings.HasSuffix(fields[0], ":latest") {
					t.Errorf("base image needs a version tag: %q", directive.value)
				}
			}
			if directive.instruction == "ADD" {
				for _, field := range fields {
					if strings.Contains(strings.ToLower(field), "http://") || strings.Contains(strings.ToLower(field), "https://") {
						t.Errorf("remote ADD: %q", directive.value)
					}
				}
			}
		}
	}
	if !strings.HasPrefix(stages[0][0].value, "golang:"+version[1]+" ") &&
		!strings.HasPrefix(stages[0][0].value, "golang:"+version[1]+"-") {
		t.Errorf("builder must use go.mod's Go %s: %s", version[1], stages[0][0].value)
	}
	for _, directive := range stages[0] {
		if directive.instruction == "RUN" && strings.Contains(directive.value, "CGO_ENABLED=0 go build") &&
			strings.Contains(directive.value, "-trimpath") && strings.Contains(directive.value, "./cmd/norn-log") {
			static = true
		}
	}
	if !static {
		t.Error("builder must build cmd/norn-log with CGO_ENABLED=0 and -trimpath")
	}
	final := make(map[string][]string)
	for _, directive := range stages[len(stages)-1] {
		final[directive.instruction] = append(final[directive.instruction], directive.value)
	}
	users := final["USER"]
	if len(users) != 1 || !regexp.MustCompile(`^[1-9][0-9]*(?::[1-9][0-9]*)?$`).MatchString(strings.Join(users, "")) {
		t.Errorf("final stage needs one numeric non-zero USER, got %q", users)
	}
	if copies := final["COPY"]; len(copies) != 1 || copies[0] != "--from=build /out/norn-log /usr/local/bin/norn-log" {
		t.Errorf("final stage must copy only the built binary, got %q", copies)
	}
	if len(final["ADD"]) != 0 {
		t.Error("final stage must not add other files")
	}
	if volumes := final["VOLUME"]; len(volumes) != 1 || volumes[0] != `["/var/lib/norn-log"]` {
		t.Errorf("only the log directory is a declared writable volume, got %q", volumes)
	}
	if len(final["ENTRYPOINT"]) != 1 {
		t.Fatal("final stage needs exactly one ENTRYPOINT")
	}
	var entrypoint []string
	if err := json.Unmarshal([]byte(final["ENTRYPOINT"][0]), &entrypoint); err != nil {
		t.Fatal(err)
	}
	if len(entrypoint) == 0 || entrypoint[0] != "/usr/local/bin/norn-log" {
		t.Fatalf("ENTRYPOINT does not run the copied binary: %q", entrypoint)
	}
	bin := deploymentBinary(t, "norn-log", t.TempDir())
	out, err := exec.Command(bin, "-help").CombinedOutput()
	// main reports flag.ErrHelp as exit 1; no server or key is opened.
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !strings.Contains(string(out), "Usage of norn-log:") {
		t.Fatalf("cannot read norn-log's flag set: %v\n%s", err, out)
	}
	flags := make(map[string]bool)
	for _, match := range regexp.MustCompile(`(?m)^  -([a-z][a-z-]*)\b`).FindAllStringSubmatch(string(out), -1) {
		flags[match[1]] = true
	}
	if len(flags) == 0 {
		t.Fatal("the flag set listed no flags")
	}
	for i := 1; i < len(entrypoint); i += 2 {
		name := strings.TrimLeft(entrypoint[i], "-")
		if !strings.HasPrefix(entrypoint[i], "-") || !flags[name] || i+1 >= len(entrypoint) {
			t.Errorf("ENTRYPOINT flag is absent from the flag set or has no value: %q", entrypoint[i])
		}
	}
	// Numeric identity is also checked as a number, so an overflowing UID
	// cannot pass merely because it contains digits.
	if len(users) == 1 {
		for _, id := range strings.Split(users[0], ":") {
			if _, err := strconv.ParseUint(id, 10, 32); err != nil {
				t.Errorf("invalid runtime identity %q: %v", id, err)
			}
		}
	}
}
