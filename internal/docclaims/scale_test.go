package docclaims

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/proof"
	"github.com/onembyte/norn/internal/tlog"
)

// These guard inputs remain tied to the implementation constants. Controls
// perturb them here, without editing protocol code or generated fixtures.
const (
	scaleEntryBytes   = cbor.MaxEntryBytes
	scaleServingBytes = tlog.MaxBundleEntryBytes
	scaleProofBytes   = proof.MaxBundleBytes
	scaleTileHeight   = tlog.TileHeight
	scaleTileWidth    = tlog.TileWidth
	scaleHashBytes    = sha256.Size
)

// scaleTypicalEntry is the typical entry size the estimates assume, in bytes:
// an assumption, stated as one, not a measurement of a production log. The
// replay fixture is the only log there is, so its mean keeps the assumption
// honest -- within scaleTypicalSlack of it -- without pinning the document to
// the fixture's exact bytes, which grow with every vector row.
const (
	scaleTypicalEntry = 420
	scaleTypicalSlack = 0.25
)

func document(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root(t), name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(string(raw)), " ")
}

func requireClaim(t *testing.T, doc, claim string) {
	t.Helper()
	if !strings.Contains(doc, strings.Join(strings.Fields(claim), " ")) {
		t.Errorf("document does not say: %s", claim)
	}
}

// A fixture average checks an estimate's input; it is not a promise about real logs.
func fixtureSizes(t *testing.T) (count, total int64) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root(t), "testdata/vectors/log/*.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		count++
		total += info.Size()
	}
	if count == 0 {
		t.Fatal("no log entries to measure")
	}
	return
}

// Hash tiles store one hash per leaf, then one per complete TileWidth group
// at each higher level. Retained partial paths can hold every preceding width.
func scaleHashes(n int64, retained bool) int64 {
	var count int64
	for n > 0 {
		if retained {
			count += retainedWidths(n)
		} else {
			count += n
		}
		n /= scaleTileWidth
	}
	return count * scaleHashBytes
}

func retainedWidths(n int64) int64 {
	width := int64(scaleTileWidth)
	remainder := n % width
	return n/width*(width*(width+1)/2) + remainder*(remainder+1)/2
}

func TestTheScaleInputsAreMeasuredAndNamed(t *testing.T) {
	doc := claimSpan(t, "THREAT-MODEL.md", "## 6. Parameters", "## 7. Explicit non-goals")
	count, total := fixtureSizes(t)
	mean := float64(total) / float64(count)
	if mean < scaleTypicalEntry*(1-scaleTypicalSlack) || mean > scaleTypicalEntry*(1+scaleTypicalSlack) {
		t.Errorf("the replay fixture's mean entry is %.1f bytes, more than a quarter from the "+
			"%d bytes the estimates assume; re-state the assumption and the tables", mean, scaleTypicalEntry)
	}
	requireClaim(t, doc, fmt.Sprintf("A typical entry is taken to be %d bytes. That is an assumption, not a measurement of a production log: the replay fixture in `testdata/vectors/log`, the only log there is, has a mean entry within a quarter of it, rejected and malformed entries included, and a guard keeps it there.", scaleTypicalEntry))
	requireClaim(t, doc, fmt.Sprintf("`MAX_ENTRY_BYTES` = %d (`internal/cbor.MaxEntryBytes`, `SPEC.md` §4.0); the serving cap `internal/tlog.MaxBundleEntryBytes` = %d.", scaleEntryBytes, scaleServingBytes))
	framed, err := tlog.EncodeBundle([][]byte{{1}})
	if err != nil {
		t.Fatal(err)
	}
	requireClaim(t, doc, fmt.Sprintf("Entry bundles add %d bytes per entry (`internal/tlog.EncodeBundle`'s uint16 framing, `SPEC.md` §6).", len(framed)-1))
	requireClaim(t, doc, fmt.Sprintf("Hash tiles have height %d, width %d (`internal/tlog.TileHeight`, `TileWidth`), and %d-byte hashes (`crypto/sha256.Size`, `SPEC.md` §6).", scaleTileHeight, scaleTileWidth, scaleHashBytes))
	requireClaim(t, doc, fmt.Sprintf("`MAX_BUNDLE_BYTES` = %d (`internal/proof.MaxBundleBytes`, `SPEC.md` §8.1) caps a portable proof bundle, not the replicated log or an entry bundle; it is not multiplied by the entry count here.", scaleProofBytes))
}

func TestTheScaleTablesAreRecomputed(t *testing.T) {
	doc := claimSpan(t, "THREAT-MODEL.md", "## 6. Parameters", "## 7. Explicit non-goals")
	framed, err := tlog.EncodeBundle([][]byte{{1}})
	if err != nil {
		t.Fatal(err)
	}
	prefix := int64(len(framed) - 1)
	for _, n := range []int64{1000, 10000, 100000, 1000000} {
		t.Run(strconv.FormatInt(n, 10), func(t *testing.T) {
			hashes := scaleHashes(n, false)
			requireClaim(t, doc, fmt.Sprintf("| %d | %d | %d | %d |", n, n*(scaleTypicalEntry+prefix)+hashes, n*(int64(scaleEntryBytes)+prefix)+hashes, hashes))
			retained := retainedWidths(n)
			hashes = scaleHashes(n, true)
			requireClaim(t, doc, fmt.Sprintf("| %d | %d | %d | %d |", n, retained*(scaleTypicalEntry+prefix)+hashes, retained*(int64(scaleEntryBytes)+prefix)+hashes, hashes))
		})
	}
	requireClaim(t, doc, "For E entries, current-head hash payload is `H(E) = sha256.Size × Σ floor(E / TileWidth^L)`, starting at L = 0 and stopping at zero; current-head payload is `E × (entry_bytes + framing_bytes) + H(E)`.")
	requireClaim(t, doc, "For retained partials, define `R(x) = floor(x / w) × w(w+1)/2 + r(r+1)/2`, where `w = TileWidth` and `r = x mod w`; substitute `R(E)` for E in entry storage and `sha256.Size × Σ R(floor(E / w^L))` for H(E).")
	requireClaim(t, doc, "N nodes hold N times the per-node payload in either table; these are estimates of file-content bytes, excluding checkpoints, filesystem metadata and allocation rounding, proof bundles, temporary writes and other caches.")
	// Check the formula against the writer rather than merely repeating it.
	for _, n := range []int{1, scaleTileWidth - 1, scaleTileWidth, scaleTileWidth + 1, scaleTileWidth*scaleTileWidth + 1} {
		tree, err := tlog.Build(make([][]byte, n))
		if err != nil {
			t.Fatal(err)
		}
		tiles, err := tree.Tiles()
		if err != nil {
			t.Fatal(err)
		}
		var bytes int64
		for _, tile := range tiles {
			bytes += int64(len(tile.Data))
		}
		if bytes != scaleHashes(int64(n), false) {
			t.Fatalf("tile formula at %d: %d, writer %d", n, scaleHashes(int64(n), false), bytes)
		}
	}
}

func productionAST(t *testing.T, path string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root(t), path), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func hasCall(f *ast.File, name string) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			found = found || fn.Name == name
		case *ast.SelectorExpr:
			found = found || fn.Sel.Name == name
		}
		return true
	})
	return found
}

func TestTheScaleReplicationAndReplayLimitsAreExplicit(t *testing.T) {
	doc := claimSpan(t, "THREAT-MODEL.md", "## 6. Parameters", "## 7. Explicit non-goals")
	for _, claim := range []string{
		"`PLAN.md` targets 10¹–10⁶ entries in closed networks; that is a design target, not a tested capacity or a configured log-size ceiling.",
		"Every node replicates the whole log (`internal/mirror.Write`) and replays from genesis on each start with a usable mirror (`internal/agent.restoreHead` → `verify` → `internal/logclient.Verify`); without a usable mirror its first successful fetch does the same. There is no snapshot or compaction path. In-process updates can resume the held replay (`internal/logclient.VerifyFrom`); that does not survive a process restart.",
		"The first table counts only files needed by the current head. The second estimates a mirror that observed every append: `internal/mirror.Write` retains earlier partial bundle and tile paths, so disk use can be much larger. It assumes every entry has the typical size or the entry cap respectively; neither table is a filesystem capacity guarantee.",
		"Raspberry Pi replay time is **unmeasured**. There is no replay benchmark in the tree; the lab must measure startup replay on the actual Pi, with its log, storage and witness policy, before treating the design target as usable capacity.",
	} {
		requireClaim(t, doc, claim)
	}
	for path, calls := range map[string][]string{
		"internal/agent/agent.go":      {"restoreHead", "Verify"},
		"internal/agent/restore.go":    {"verify"},
		"internal/logclient/client.go": {"New", "fetchEntries", "Apply"},
		"internal/mirror/mirror.go":    {"EncodeBundle", "Tiles", "EntryBundlePath"},
	} {
		f := productionAST(t, path)
		for _, call := range calls {
			if !hasCall(f, call) {
				t.Errorf("%s no longer calls %s; re-audit the scale claim", path, call)
			}
		}
	}
	if !strings.Contains(document(t, "PLAN.md"), "10¹ – 10⁶ entries, full replication on every node") {
		t.Error("scale target changed; update the threat model")
	}
	err := filepath.WalkDir(root(t), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && strings.HasPrefix(fn.Name.Name, "Benchmark") && strings.Contains(strings.ToLower(fn.Name.Name), "replay") {
				t.Errorf("%s now measures replay; update the unmeasured benchmark claim", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
