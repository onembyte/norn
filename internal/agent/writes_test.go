package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What the agent keeps, it keeps through something that owns the format and
// the failure modes: internal/durable for evidence, whose presence is the
// freeze; proven.Write for the published view; mirror.Write for the copy of
// the log. A bare os.WriteFile here would be a write a power cut can tear --
// and no behavioural test can see the difference for a file that did not
// exist before, so this test reads the source instead.
func TestTheAgentWritesNoFileDirectly(t *testing.T) {
	forbidden := map[string]bool{"WriteFile": true, "Create": true, "OpenFile": true,
		"CreateTemp": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" && forbidden[sel.Sel.Name] {
				t.Errorf("%s: os.%s -- write through internal/durable, proven.Write or "+
					"mirror.Write instead", fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}
