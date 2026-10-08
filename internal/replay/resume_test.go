package replay

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/onembyte/norn/internal/tlog"
)

// servedEntries reads every entry a served directory holds, bundle by bundle,
// in log order.
func servedEntries(t *testing.T, dir string, size int) [][]byte {
	t.Helper()
	var out [][]byte
	for index := 0; len(out) < size; index++ {
		width := min(size-len(out), tlog.TileWidth)
		name := filepath.Join(dir, tlog.EntryBundlePath(int64(index), width))
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := tlog.DecodeBundle(raw)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, entries...)
	}
	return out
}

// canonical is the state as `state.json` would carry it: the bytes a second
// implementer compares against, so "the same" means byte for byte.
func canonical(t *testing.T, anchor Anchor, apply func(*Replayer)) []byte {
	t.Helper()
	p := New(anchor)
	apply(p)
	raw, err := p.State().MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// H4-a. `Replay` is a fold over the log; a node that re-runs it from entry 0
// on every grown head does work proportional to the log's whole history on
// every cycle. The fold is made resumable, and the property that makes it
// usable is this one: applying a prefix and then the rest is the same as
// applying the whole, byte for byte, at every split -- including the splits
// that separate a `dup-entry` copy from its original, which is why the seen
// set has to travel with the state.
func TestAReplayResumedAtAnySplitIsTheWholeReplay(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	whole := canonical(t, anchor, func(p *Replayer) { p.Apply(entries...) })
	for k := 0; k <= len(entries); k++ {
		split := canonical(t, anchor, func(p *Replayer) {
			p.Apply(entries[:k]...)
			p.Apply(entries[k:]...)
		})
		if !bytes.Equal(split, whole) {
			t.Fatalf("resumed at %d of %d, the state differs from one replay", k, len(entries))
		}
	}
}

// The same over `served-large/`, whose 300 entries cross a full tile: every
// tile boundary and a sample of the splits between.
func TestALargeLogResumedAcrossItsTileBoundariesIsTheWholeReplay(t *testing.T) {
	anchor, _, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	entries := servedEntries(t, filepath.Join(vectorRoot(), "served-large"), 300)
	whole := canonical(t, anchor, func(p *Replayer) { p.Apply(entries...) })
	full := New(anchor)
	if full.Apply(entries...).Size != 300 {
		t.Fatalf("served-large does not replay under the fixture anchor; the property would be vacuous")
	}
	splits := map[int]bool{0: true, 1: true, 255: true, 256: true, 257: true, 299: true, 300: true}
	for k := 0; k <= 300; k += 7 {
		splits[k] = true
	}
	var ordered []int
	for k := range splits {
		ordered = append(ordered, k)
	}
	sort.Ints(ordered)
	for _, k := range ordered {
		split := canonical(t, anchor, func(p *Replayer) {
			p.Apply(entries[:k]...)
			p.Apply(entries[k:]...)
		})
		if !bytes.Equal(split, whole) {
			t.Fatalf("resumed at %d of 300, the state differs from one replay", k)
		}
	}
}

// A bad genesis aborts the fold: §5.1 says nothing after it is this
// network's. Resuming must not quietly start applying entries onto the empty
// state the abort left -- and the entry that shows it is a valid genesis,
// which an empty state would otherwise take as its first. So the fold runs
// under the fixture's anchor, which accepts the fixture's genesis, with a
// refused genesis before it. (Each `genesis/` case's own anchor refuses the
// real genesis too, so under those anchors a forgotten abort is invisible.)
func TestAFoldAbortedByABadGenesisStaysAborted(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	cases, _ := filepath.Glob(filepath.Join(vectorRoot(), "genesis", "*", "manifest.json"))
	if len(cases) == 0 {
		t.Fatal("no genesis cases")
	}
	tried := 0
	for _, manifestPath := range cases {
		name := filepath.Base(filepath.Dir(manifestPath))
		_, bad, _ := loadCase(t, filepath.Dir(manifestPath))
		if len(bad) != 1 || Replay(anchor, bad).Size != 0 {
			continue // `01-hash-mismatch` is the real genesis under another anchor
		}
		tried++
		log := append([][]byte{bad[0]}, entries...)
		whole := canonical(t, anchor, func(p *Replayer) { p.Apply(log...) })
		split := canonical(t, anchor, func(p *Replayer) {
			p.Apply(log[:1]...)
			p.Apply(log[1:]...)
		})
		if !bytes.Equal(split, whole) {
			t.Fatalf("%s: resumed after the bad genesis, the fold went on", name)
		}
		if st := New(anchor).Apply(log...); st.Size != 0 || len(st.Rejected) != 1 {
			t.Fatalf("%s: a bad genesis should leave size 0 and one rejection, got %d and %d",
				name, st.Size, len(st.Rejected))
		}
	}
	if tried == 0 {
		t.Fatal("no genesis refused under the fixture anchor among the cases")
	}
}
