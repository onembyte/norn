package depgraph

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// SPEC §3.1 (D-072 (c)): every Ed25519 verification is NORN-ED25519-v1, and
// internal/ed25519v1 is the only place it is written down. Go's own
// crypto/ed25519.Verify accepts what the predicate refuses -- the identity as
// a key signs every message under it -- so a call to it anywhere else is a
// verifier that disagrees with the specification. Signing with crypto/ed25519
// is fine; verifying with it is not.
//
// Test files may still call it: there it is an independent oracle, checking
// that what Norn signs is ordinary Ed25519, and it decides nothing.
func TestNothingButEd25519v1VerifiesWithCryptoEd25519(t *testing.T) {
	root := filepath.Join("..", "..")
	exempt := filepath.Join(root, "internal", "ed25519v1")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path == exempt || name == "testdata" || name == "vendor" ||
				(strings.HasPrefix(name, ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, use := range verifierUses(t, path) {
			t.Errorf("%s calls crypto/ed25519's %s; verify with ed25519v1.Verify (SPEC §3.1)", use, use.name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type use struct {
	token.Position
	name string
}

func (u use) String() string { return u.Position.String() }

// verifierUses finds every reference to Verify or VerifyWithOptions in
// crypto/ed25519 (or golang.org/x/crypto/ed25519, which forwards to it) under
// whatever name the file imports it as -- a call, or a function value.
func verifierUses(t *testing.T, path string) []use {
	t.Helper()
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, spec := range file.Imports {
		imported, _ := strconv.Unquote(spec.Path.Value)
		if imported != "crypto/ed25519" && imported != "golang.org/x/crypto/ed25519" {
			continue
		}
		name := "ed25519"
		if spec.Name != nil {
			name = spec.Name.Name
		}
		names[name] = true
	}
	var found []use
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if ok && names[pkg.Name] && (sel.Sel.Name == "Verify" || sel.Sel.Name == "VerifyWithOptions") {
			found = append(found, use{files.Position(sel.Pos()), sel.Sel.Name})
		}
		return true
	})
	return found
}
