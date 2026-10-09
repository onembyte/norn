package docclaims

import (
	"go/ast"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Inspect the dispatch table, not usage text: an advertised or commented
// command is not an implementation. This also catches unadvertised commands.
func commandTable(t *testing.T) map[string]bool {
	t.Helper()
	commands := map[string]bool{}
	for _, decl := range productionAST(t, "cmd/norn/main.go").Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if name.Name != "commands" {
					continue
				}
				table, ok := value.Values[i].(*ast.CompositeLit)
				if !ok {
					t.Fatal("command table is no longer a literal; update the guard")
				}
				for _, element := range table.Elts {
					pair, ok := element.(*ast.KeyValueExpr)
					if !ok {
						t.Fatal("unrecognised command table entry")
					}
					key, ok := pair.Key.(*ast.BasicLit)
					if !ok {
						t.Fatal("nonliteral command name")
					}
					name, err := strconv.Unquote(key.Value)
					if err != nil {
						t.Fatal(err)
					}
					commands[name] = true
				}
			}
		}
	}
	if len(commands) == 0 {
		t.Fatal("found no command table")
	}
	return commands
}

func flagNames(t *testing.T, path string) map[string]bool {
	t.Helper()
	flags := map[string]bool{}
	ast.Inspect(productionAST(t, path), func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || receiver.Name != "fs" {
			return true
		}
		index := 0
		switch selector.Sel.Name {
		case "Var":
			index = 1
		case "String", "Bool", "Int", "Int64", "Uint64", "Duration":
		default:
			return true
		}
		if len(call.Args) <= index {
			t.Fatal("flag registration without a name")
		}
		literal, ok := call.Args[index].(*ast.BasicLit)
		if !ok {
			t.Fatal("nonliteral flag name; update the guard")
		}
		name, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		flags[name] = true
		return true
	})
	if len(flags) == 0 {
		t.Fatalf("no flags found in %s", path)
	}
	return flags
}

func claimSpan(t *testing.T, file, start, end string) string {
	t.Helper()
	doc := document(t, file)
	at := strings.Index(doc, start)
	if at < 0 {
		t.Fatalf("%s has no claim starting %q", file, start)
	}
	doc = doc[at:]
	last := strings.Index(doc[len(start):], end)
	if last < 0 {
		t.Fatalf("%s has no end %q after %q", file, end, start)
	}
	return doc[:len(start)+last]
}

func plannedClaim(t *testing.T, span string, exists bool) {
	t.Helper()
	planned := strings.Contains(strings.ToLower(span), "planned")
	if planned == exists {
		t.Errorf("implementation exists=%t but planned=%t: %s", exists, planned, span)
	}
}

func TestTheEnrollmentPlansMatchTheCommandTableAndFlags(t *testing.T) {
	commands := commandTable(t)
	for _, c := range []struct {
		name, start, end string
		exists           bool
	}{
		{"paper-tier", "| 3 |", "| — |", flagNames(t, "cmd/norn/init.go")["paper"]},
		{"paper-ceremony", "The paper-root steps", "Org default:", flagNames(t, "cmd/norn/init.go")["mnemonic"]},
		{"pending-post", "→ optionally POSTs", "admin$", productionHasLiteral(t, "internal/logserver", "/pending")},
		{"pending-flag", "admin$", "pi-cam wg=", flagNames(t, "cmd/norn/sign.go")["pending"]},
		{"trust-import", "device$ #", "nornd starts", commands["trust"]},
		{"rotate", "- **Rotate**", "- **Revoke**", commands["rotate"]},
		{"revoke", "- **Revoke**", "- **Expiry**", commands["revoke"]},
		{"migrate", "| R5 |", "| R6 |", commands["migrate"]},
		{"restore", "| R6 |", "| R7 |", productionHasLiteral(t, "cmd/norn-log", "restore") || flagNames(t, "cmd/norn-log/main.go")["from"]},
		{"paper-ux", "3. Paper keys", "4. Any flow", flagNames(t, "cmd/norn/init.go")["paper"]},
	} {
		t.Run(c.name, func(t *testing.T) {
			plannedClaim(t, claimSpan(t, "ENROLLMENT.md", c.start, c.end), c.exists)
		})
	}
	// The examples are useful only if their flags still exist in the handler.
	for command, names := range map[string][]string{
		"rotate": {"trust", "device", "wg-key", "key", "yes", "o", "new-key", "role", "in"},
		"revoke": {"trust", "device", "reason", "key", "o", "in", "role"},
	} {
		flags := flagNames(t, "cmd/norn/"+command+".go")
		for _, name := range names {
			if !flags[name] {
				t.Errorf("documented %s flag %s no longer exists", command, name)
			}
		}
	}
}

func TestRotationIsNotRevocation(t *testing.T) {
	for _, claim := range []struct {
		file, phrase string
	}{
		{"ENROLLMENT.md", "Rotation does not revoke"},
		{"THREAT-MODEL.md", "verifier-side retirement is recorded for v1.1"},
	} {
		t.Run(claim.file, func(t *testing.T) {
			if !strings.Contains(document(t, claim.file), claim.phrase) {
				t.Errorf("%s does not say %q", claim.file, claim.phrase)
			}
		})
	}
}

// Only production string literals count. Comments about a future exporter,
// tests and an unrelated monitor inbox cannot make a node endpoint exist.
func productionHasLiteral(t *testing.T, dir, want string) bool {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(filepath.Join(root(t), dir), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		rel, err := filepath.Rel(root(t), path)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(productionAST(t, rel), func(n ast.Node) bool {
			literal, ok := n.(*ast.BasicLit)
			if !ok {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err == nil && (value == want || strings.Contains(value, want+"{")) {
				found = true
			}
			return true
		})
	}
	return found
}

func TestTheNodeMetricsAndReconcileFileClaimsMatchTheCode(t *testing.T) {
	doc := claimSpan(t, "GOSSIP.md", "## 9. Metrics", "`norn_checkpoint_size`")
	for _, name := range []string{
		"/metrics", "norn_checkpoint_size", "norn_checkpoint_age_seconds", "norn_state",
		"norn_gossip_peers_polled_total", "norn_gossip_adopted_from", "norn_fork_evidence_total",
		"norn_replay_rejected_total", "norn_clock_skew_seconds", "norn_reconcile_seconds",
		"norn_evicted_peers_total", "norn_unproven_peers",
	} {
		t.Run(name, func(t *testing.T) {
			exists := false
			for _, dir := range []string{"cmd/nornd", "internal"} {
				exists = exists || productionHasLiteral(t, dir, name)
			}
			plannedClaim(t, doc, exists)
		})
	}
	reconcile := claimSpan(t, "ENFORCEMENT.md", "Idempotent;", "Swap attack check")
	for _, name := range []string{"reconcile.json", "norn_reconcile_seconds"} {
		t.Run(name, func(t *testing.T) {
			for _, dir := range []string{"cmd/nornd", "internal"} {
				if productionHasLiteral(t, dir, name) {
					t.Errorf("%s now exists in %s; update the negative claim", name, dir)
				}
			}
			requireClaim(t, reconcile, "does not publish a `reconcile.json` file or the `norn_reconcile_seconds` histogram")
		})
	}
}

func TestTheREADMERetainsItsDeploymentStatus(t *testing.T) {
	requireClaim(t, document(t, "README.md"), "No Norn has ever guarded a network anyone depends on")
}
