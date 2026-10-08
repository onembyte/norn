package logclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/tlogstore"
)

// heldAt is the Result a node holds after verifying an honest log at `size`
// entries: its tree, its fold, and a checkpoint for that head. The signature
// on that checkpoint is not needed -- a held head was verified when it was
// adopted -- so the tree's own head stands in for it.
func heldAt(t *testing.T, anchor Anchor, honest string, size int64) *Result {
	t.Helper()
	cp := checkpointIn(t, honest, "checkpoint", anchor)
	entries, err := fetchEntries(Dir(honest), cp.Size)
	if err != nil {
		t.Fatal(err)
	}
	entries = entries[:size]
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	fold := replay.New(anchor.Anchor)
	return &Result{Checkpoint: tree.Checkpoint(anchor.Origin), Tree: tree,
		State: fold.Apply(entries...), Served: entries, fold: fold}
}

// pathsBeyond lists what an incremental verifier fetches when it holds `held`
// and the log has grown to `size`: the checkpoint, every bundle that holds an
// entry at or past the held size, and every tile whose path -- width included
// -- is not already among the held tree's tiles. A case whose defect lies
// elsewhere is one the held head already vouched for, and H3's periodic full
// re-verify is what catches it later.
func pathsBeyond(t *testing.T, held *Result, size int64, honest string) map[string]bool {
	t.Helper()
	out := map[string]bool{"checkpoint": true}
	// At the held size there is nothing new, and no bundle is fetched at all.
	for index := int64(0); size > held.Tree.Size() && index*tlog.TileWidth < size; index++ {
		if (index+1)*tlog.TileWidth <= held.Tree.Size() {
			continue // a full bundle below the held size never changes
		}
		width := int(min(size-index*tlog.TileWidth, tlog.TileWidth))
		out[tlog.EntryBundlePath(index, width)] = true
	}
	entries, err := fetchEntries(Dir(honest), size)
	if err != nil {
		t.Fatal(err)
	}
	full, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	heldTiles, _ := held.Tree.Tiles()
	unchanged := map[string]bool{}
	for _, tile := range heldTiles {
		unchanged[tile.Path()] = true
	}
	tiles, _ := full.Tiles()
	for _, tile := range tiles {
		if !unchanged[tile.Path()] {
			out[tile.Path()] = true
		}
	}
	return out
}

// changedPaths lists every path at which a case's served directory differs
// from the honest log it is served over: a file changed, missing or added.
// Visibility to an incremental verifier is decided from these, not from what
// a cases.json says the case is about -- a detect/ case that serves the held
// checkpoint over a tampered bundle changes nothing the verifier fetches.
func changedPaths(t *testing.T, caseDir, honest string) []string {
	t.Helper()
	files := map[string]bool{}
	for _, root := range []string{caseDir, honest} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(rel)] = true
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var out []string
	for rel := range files {
		a, errA := os.ReadFile(filepath.Join(caseDir, filepath.FromSlash(rel)))
		b, errB := os.ReadFile(filepath.Join(honest, filepath.FromSlash(rel)))
		if (errA == nil) != (errB == nil) || !bytes.Equal(a, b) {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// sameOutcome compares what Verify and VerifyFrom said about one served log.
func sameOutcome(t *testing.T, name string, full *Result, fullErr error, inc *Result, incErr error) {
	t.Helper()
	fullCode, _ := refusal.CodeOf(fullErr)
	incCode, _ := refusal.CodeOf(incErr)
	if (fullErr == nil) != (incErr == nil) || fullCode != incCode {
		t.Fatalf("%s: Verify says %q (%v), VerifyFrom says %q (%v)", name, fullCode, fullErr, incCode, incErr)
	}
	var fullFork, incFork *ForkError
	if errors.As(fullErr, &fullFork) != errors.As(incErr, &incFork) {
		t.Fatalf("%s: only one of the two is a *ForkError", name)
	}
	if fullErr != nil {
		return
	}
	if full.Checkpoint != inc.Checkpoint || full.Tree.Head() != inc.Tree.Head() || len(full.Served) != len(inc.Served) {
		t.Fatalf("%s: the two verified different heads", name)
	}
	a, _ := full.State.MarshalCanonical()
	b, _ := inc.State.MarshalCanonical()
	if !bytes.Equal(a, b) {
		t.Fatalf("%s: the two replayed to different states", name)
	}
}

// sizesFor samples the held sizes for a log of `size` entries: the ends, the
// middle, where the tile arithmetic has edges, and any size a case names.
func sizesFor(size int64, named ...int64) []int64 {
	set := map[int64]bool{1: true, 2: true, 3: true, size / 2: true, size - 1: true, size: true}
	for _, edge := range []int64{tlog.TileWidth - 1, tlog.TileWidth, tlog.TileWidth + 1} {
		if edge < size {
			set[edge] = true
		}
	}
	for _, n := range named {
		if n > 0 && n <= size {
			set[n] = true
		}
	}
	var out []int64
	for n := range set {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// H4-b. A node that holds a head re-fetched and re-verified the whole log on
// every cycle. VerifyFrom fetches what lies beyond the held head and verifies
// the rest from what it holds; what it must not do is reach a different
// verdict. For every held size and every bad served log in the suite whose
// defect an incremental verifier can see, the two agree code for code -- and
// where the defect lies below the held head, VerifyFrom accepts, by design,
// and this test says so.
func TestVerifyFromAgreesWithVerifyOnEveryCaseItCanSee(t *testing.T) {
	anchor := shippedLogAnchor(t)

	type served struct {
		name   string
		dir    string
		stored *tlog.Checkpoint // detect/ cases carry their own stored head
	}
	type suite struct {
		honest string
		sizes  []int64
		cases  []served
	}
	var suites []suite

	// checkpoints-bad/ and detect/ are served over served/.
	honest := filepath.Join(vectorRoot(), "served")
	var over145 suite
	over145.honest = honest
	var bad struct {
		Cases []string `json:"cases"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", "cases.json"))), &bad); err != nil {
		t.Fatal(err)
	}
	for _, name := range bad.Cases {
		checkpoint := readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", name+".checkpoint"))
		over145.cases = append(over145.cases, served{name: "checkpoints-bad/" + name, dir: servedWith(t, honest, checkpoint)})
	}
	detect := filepath.Join(vectorRoot(), "detect")
	var doc struct {
		Cases []struct{ Name, Stored, Serve, Outcome string } `json:"cases"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(detect, "cases.json"))), &doc); err != nil {
		t.Fatal(err)
	}
	var storedSizes []int64
	for _, c := range doc.Cases {
		stored := checkpointIn(t, detect, c.Stored, anchor)
		storedSizes = append(storedSizes, stored.Size)
		over145.cases = append(over145.cases, served{name: "detect/" + c.Name, dir: filepath.Join(detect, c.Serve), stored: &stored})
	}
	over145.sizes = sizesFor(checkpointIn(t, honest, "checkpoint", anchor).Size, storedSizes...)
	suites = append(suites, over145)

	// served-bad/ is served over whatever its cases.json says (served-large/).
	negatives, _, serveOver := servedNegatives(t)
	large := filepath.Join(vectorRoot(), serveOver)
	var overLarge suite
	overLarge.honest = large
	for _, c := range negatives {
		overLarge.cases = append(overLarge.cases, served{name: "served-bad/" + c.Name, dir: c.apply(t, serveOver)})
	}
	overLarge.sizes = sizesFor(checkpointIn(t, large, "checkpoint", anchor).Size)
	suites = append(suites, overLarge)

	for _, su := range suites {
		full := checkpointIn(t, su.honest, "checkpoint", anchor)
		for _, size := range su.sizes {
			held := heldAt(t, anchor, su.honest, size)
			visible := pathsBeyond(t, held, full.Size, su.honest)
			for _, c := range su.cases {
				a := anchor
				if c.stored != nil {
					// A detect/ case says what the node holds; the held result
					// must say the same, or the comparison is not the case's.
					if c.stored.Size != size {
						continue
					}
					a.Stored, a.Held = c.stored, held.Tree
				} else {
					cp := held.Checkpoint
					a.Stored, a.Held = &cp, held.Tree
				}
				fullResult, fullErr := Verify(Dir(c.dir), a)
				incResult, incErr := VerifyFrom(held, Dir(c.dir), a)
				changed := changedPaths(t, c.dir, su.honest)
				// A case that changes nothing is the honest log itself (an
				// honest grown head under an earlier stored one): compare.
				seen := len(changed) == 0
				for _, p := range changed {
					if visible[p] {
						seen = true
					}
				}
				label := c.name + " held at " + strconv.FormatInt(size, 10)
				if seen {
					sameOutcome(t, label, fullResult, fullErr, incResult, incErr)
					continue
				}
				// Below the held head: the held head vouched for it already.
				if incErr != nil {
					t.Errorf("%s: the defect lies below the held head, yet VerifyFrom refused: %v", label, incErr)
				}
				if fullErr == nil {
					t.Errorf("%s: a served-bad case that Verify accepts", label)
				}
			}
		}
	}
}

// counting records every path a fetcher was asked for and answered.
type counting struct {
	Fetcher
	fetched map[string]int
}

func (c *counting) Fetch(path string) ([]byte, error) {
	raw, err := c.Fetcher.Fetch(path)
	if err == nil {
		c.fetched[path]++
	}
	return raw, err
}

func (c *counting) paths() []string {
	var out []string
	for p := range c.fetched {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// largeLog is a 300-entry log this package signs and cosigns itself: the
// fixture's entries, then filler the replay refuses and the tree holds. It
// crosses a full bundle, so growing it by one touches one bundle of two and
// one tile of three -- which is what makes fetching only what changed
// observable at all.
func largeLog(t *testing.T) (string, Anchor, *tlogstore.Store) {
	t.Helper()
	inner, entries := loadFixture(t)
	dir := t.TempDir()
	key := logKey(t)
	store, err := tlogstore.Open(dir, "norn/test", key, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(cosign.Append(witnesses(t), cosign.At(cosignedAt)))))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; len(entries) < 300; i++ {
		entries = append(entries, []byte("filler "+strconv.Itoa(i)))
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	return dir, Anchor{Anchor: inner, Origin: "norn/test",
		LogKeys: []string{verifierKey(t, key, "norn/test")},
		Policy:  policyOver(t, "norn/test", witnessNames, 2)}, store
}

// One appended entry costs exactly the checkpoint, the bundle it landed in
// and the tiles that changed; an unchanged log costs the checkpoint alone.
func TestOneAppendedEntryFetchesOnlyWhatChanged(t *testing.T) {
	dir, anchor, store := largeLog(t)
	held, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}
	if held.Checkpoint.Size != 300 {
		t.Fatalf("size = %d", held.Checkpoint.Size)
	}
	anchor.Stored, anchor.Held = &held.Checkpoint, held.Tree

	// Nothing new: the checkpoint says so, and nothing else is asked for.
	fetcher := &counting{Fetcher: Dir(dir), fetched: map[string]int{}}
	if _, err := VerifyFrom(held, fetcher, anchor); err != nil {
		t.Fatal(err)
	}
	if got := fetcher.paths(); strings.Join(got, " ") != "checkpoint" {
		t.Errorf("an unchanged log cost %v; want the checkpoint alone", got)
	}

	if _, err := store.Append([]byte("one more entry, which replay will refuse and the tree will hold")); err != nil {
		t.Fatal(err)
	}
	fetcher = &counting{Fetcher: Dir(dir), fetched: map[string]int{}}
	grown, err := VerifyFrom(held, fetcher, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if grown.Checkpoint.Size != 301 || len(grown.Served) != 301 {
		t.Fatalf("grew to %d, served %d", grown.Checkpoint.Size, len(grown.Served))
	}
	// Bundle 0 and level-0 tile 0 are full and unchanged; the level-1 tile
	// has the same one hash and the same path. Only the partials grew.
	want := []string{"checkpoint", tlog.EntryBundlePath(1, 45), tlog.TilePath(0, 1, 45)}
	sort.Strings(want)
	if got := fetcher.paths(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("fetched %v, want exactly %v", got, want)
	}
}

// The bundle the held size falls in is refetched whole, and its entries
// below the held size must be the held ones. A log that rewrote one of them
// -- under the honest checkpoint, so the head still matches what the held
// tree plus the fresh entries would give -- is not an extension of what this
// node holds, and is handed to Verify, which refuses it as `head`.
func TestARewrittenEntryBelowTheHeldSizeIsNotAcceptedAsAnExtension(t *testing.T) {
	dir, anchor, _ := largeLog(t)
	held := heldAt(t, anchor, dir, 299)
	anchor.Stored, anchor.Held = &held.Checkpoint, held.Tree

	// Entry 256 is the first of the partial bundle, below the held 299.
	path := filepath.Join(dir, filepath.FromSlash(tlog.EntryBundlePath(1, 44)))
	entries, err := tlog.DecodeBundle([]byte(readFile(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	entries[0] = append([]byte("rewritten: "), entries[0]...)
	raw, err := tlog.EncodeBundle(entries)
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, string(raw))

	_, fullErr := Verify(Dir(dir), anchor)
	_, incErr := VerifyFrom(held, Dir(dir), anchor)
	fullCode, _ := refusal.CodeOf(fullErr)
	incCode, _ := refusal.CodeOf(incErr)
	if fullCode != refusal.Head {
		t.Fatalf("Verify refused as %q (%v), want head", fullCode, fullErr)
	}
	if incErr == nil || incCode != fullCode {
		t.Fatalf("VerifyFrom said %q (%v); a rewritten held entry must get Verify's answer", incCode, incErr)
	}
}
