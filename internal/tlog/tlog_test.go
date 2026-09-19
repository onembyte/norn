package tlog

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	upstream "golang.org/x/mod/sumdb/tlog"

	"github.com/onembyte/norn/internal/entry"
)

// Written from c2sp.org/tlog-tiles and c2sp.org/tlog-checkpoint. The Merkle
// mathematics is x/mod/sumdb/tlog's -- reusing it rather than hand-rolling a
// tree is ground rule 3, and a hand-rolled tree is exactly the kind of code
// that looks right and is subtly wrong. What is written here is the C2SP path
// layout, which x/mod does not implement: it uses the sumdb scheme instead.

func TestLeafHashAgreesWithUpstreamAndWithEntry(t *testing.T) {
	for _, data := range [][]byte{{}, {0x00}, []byte("hello"), make([]byte, 300)} {
		ours := LeafHash(data)
		if up := upstream.RecordHash(data); ours != up {
			t.Errorf("leaf hash disagrees with x/mod: %x vs %x", ours, up)
		}
		if got := entry.LeafHash(data); string(got) != string(ours[:]) {
			t.Errorf("leaf hash disagrees with internal/entry: %x vs %x", got, ours)
		}
	}
}

// The chunked path encoding is a classic interop bug: N is written as 3-digit
// groups, every group but the last prefixed with "x".
func TestTilePathsFollowTheC2SPLayout(t *testing.T) {
	cases := []struct {
		level int
		index int64
		width int
		want  string
	}{
		{0, 0, 256, "tile/0/000"},
		{0, 1, 256, "tile/0/001"},
		{0, 255, 256, "tile/0/255"},
		{1, 0, 256, "tile/1/000"},
		{0, 1000, 256, "tile/0/x001/000"},
		{0, 1234, 256, "tile/0/x001/234"},
		{0, 1234067, 256, "tile/0/x001/x234/067"},
		{0, 0, 1, "tile/0/000.p/1"},
		{0, 0, 255, "tile/0/000.p/255"},
		{0, 1234, 17, "tile/0/x001/234.p/17"},
	}
	for _, c := range cases {
		if got := TilePath(c.level, c.index, c.width); got != c.want {
			t.Errorf("TilePath(%d, %d, %d) = %q, want %q", c.level, c.index, c.width, got, c.want)
		}
	}
}

func TestEntryBundlePathsShareTheLayout(t *testing.T) {
	cases := map[string]struct {
		index int64
		width int
	}{
		"tile/entries/000":           {0, 256},
		"tile/entries/x001/234":      {1234, 256},
		"tile/entries/x001/x234/067": {1234067, 256},
		"tile/entries/000.p/7":       {0, 7},
	}
	for want, c := range cases {
		if got := EntryBundlePath(c.index, c.width); got != want {
			t.Errorf("EntryBundlePath(%d, %d) = %q, want %q", c.index, c.width, got, want)
		}
	}
}

func TestPartialWidthIsOmittedOnlyWhenFull(t *testing.T) {
	if strings.Contains(TilePath(0, 0, TileWidth), ".p/") {
		t.Error("a full tile must not carry a .p suffix")
	}
	if !strings.Contains(TilePath(0, 0, TileWidth-1), ".p/") {
		t.Error("a partial tile must carry its width")
	}
}

func TestCheckpointFormatting(t *testing.T) {
	root := [32]byte{1, 2, 3}
	cp := Checkpoint{Origin: "norn/abc", Size: 42, Root: root}
	text := cp.Marshal()
	lines := strings.Split(text, "\n")
	if len(lines) != 4 || lines[3] != "" {
		t.Fatalf("a checkpoint is three lines and a trailing newline, got %q", text)
	}
	if lines[0] != "norn/abc" || lines[1] != "42" {
		t.Errorf("origin/size lines wrong: %q", text)
	}
	if lines[2] != base64.StdEncoding.EncodeToString(root[:]) {
		t.Errorf("root must be standard base64: %q", lines[2])
	}

	back, err := ParseCheckpoint(text)
	if err != nil {
		t.Fatal(err)
	}
	if back.Origin != cp.Origin || back.Size != cp.Size || back.Root != cp.Root {
		t.Errorf("round trip lost information: %+v", back)
	}
}

func TestParseCheckpointRejectsMalformed(t *testing.T) {
	for name, text := range map[string]string{
		"no trailing newline": "norn/abc\n42\nAAAA",
		"empty origin":        "\n42\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n",
		"size not a number":   "norn/abc\nmany\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n",
		"size with a plus":    "norn/abc\n+42\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n",
		"leading zero size":   "norn/abc\n042\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n",
		"root not base64":     "norn/abc\n42\nnot base64!\n",
		"root wrong length":   "norn/abc\n42\n" + base64.StdEncoding.EncodeToString(make([]byte, 16)) + "\n",
		"extension line":      "norn/abc\n42\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\nextra\n",
	} {
		if _, err := ParseCheckpoint(text); err == nil {
			t.Errorf("%s: should have been rejected", name)
		}
	}
}

// A real tree over the suite's own entries, with inclusion proofs that must
// verify against the head -- the first time §6 and §8 touch actual data.
func TestTreeOverTheSuiteEntriesWithInclusionProofs(t *testing.T) {
	entries := loadLogEntries(t)
	if len(entries) < 80 {
		t.Fatalf("expected the fixture log, found %d entries", len(entries))
	}
	tree, err := Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Size() != int64(len(entries)) {
		t.Fatalf("tree size %d, want %d", tree.Size(), len(entries))
	}
	for _, index := range []int64{0, 1, 7, 42, int64(len(entries)) - 1} {
		proof, err := tree.InclusionProof(index)
		if err != nil {
			t.Fatalf("proof for %d: %v", index, err)
		}
		if err := upstream.CheckRecord(proof, tree.Size(), tree.Head(),
			index, LeafHash(entries[index])); err != nil {
			t.Errorf("inclusion proof for %d does not verify: %v", index, err)
		}
	}
}

func TestATamperedLeafBreaksItsProof(t *testing.T) {
	entries := loadLogEntries(t)
	tree, err := Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tree.InclusionProof(3)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), entries[3]...)
	tampered[len(tampered)/2] ^= 0x01
	if err := upstream.CheckRecord(proof, tree.Size(), tree.Head(), 3,
		LeafHash(tampered)); err == nil {
		t.Error("a proof must not verify for a leaf that was altered")
	}
}

func TestConsistencyProofBetweenTwoSizes(t *testing.T) {
	entries := loadLogEntries(t)
	older, err := Build(entries[:20])
	if err != nil {
		t.Fatal(err)
	}
	newer, err := Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := newer.ConsistencyProof(older.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := upstream.CheckTree(proof, newer.Size(), newer.Head(),
		older.Size(), older.Head()); err != nil {
		t.Errorf("consistency proof does not verify: %v", err)
	}
}

func loadLogEntries(t *testing.T) [][]byte {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "log", "*.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, 0, len(matches))
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}
