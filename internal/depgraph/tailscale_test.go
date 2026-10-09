package depgraph

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func tailscaleImports(dir string) ([]string, error) {
	// Inspect imports without building or resolving them. Build tags must not
	// hide a forbidden dependency on the platform where this guard runs.
	seen := map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			dep, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if strings.HasPrefix(dep, "tailscale.com/") {
				seen[dep] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var forbidden []string
	for dep := range seen {
		forbidden = append(forbidden, dep)
	}
	sort.Strings(forbidden)
	return forbidden, nil
}

// A missing module must not hide a forbidden import: the guard reports the
// architecture violation before anyone tries to download tailscale.com.
func TestTheTailscaleGuardFindsAnImportWithoutTheModule(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":          "module scratch\n\ngo 1.26.0\n",
		"scratch.go":      "package scratch\nimport _ \"tailscale.com/client/local\"\n",
		"scratch_test.go": "package scratch_test\nimport _ \"tailscale.com/types/key\"\n",
		"excluded.go":     "//go:build norn_never_enabled\n\npackage scratch\nimport _ \"tailscale.com/ipn\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := tailscaleImports(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "tailscale.com/client/local,tailscale.com/ipn,tailscale.com/types/key" {
		t.Fatalf("forbidden imports = %v; missing tailscale.com import", got)
	}
}

// H10 pays for two LocalAPI endpoints, not for tailscale.com's client or its
// transitive modules. There is no package in this repository allowed to import
// it, including test packages and files excluded by build tags.
func TestNoPackageImportsTailscale(t *testing.T) {
	got, err := tailscaleImports(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, dep := range got {
		t.Errorf("forbidden dependency %s: H10 uses a minimal LocalAPI client, with no tailscale.com module", dep)
	}
}
