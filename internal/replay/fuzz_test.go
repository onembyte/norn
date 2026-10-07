package replay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/trust"
)

// Replay consumes bytes chosen by an untrusted log operator. Fixture prefixes
// let mutations reach handlers with enrollment and governance state in place.
func FuzzReplayNeverPanics(f *testing.F) {
	anchor, entries := replayFuzzCorpus(f)
	for i, raw := range entries {
		f.Add(uint16(i), raw)
	}
	f.Add(uint16(0), []byte{})
	f.Add(uint16(0), []byte{0xa0})
	f.Fuzz(func(t *testing.T, prefix uint16, raw []byte) {
		n := int(prefix) % len(entries)
		log := append(append([][]byte(nil), entries[:n]...), raw)
		st := Replay(anchor, log)
		if _, err := st.MarshalCanonical(); err != nil {
			t.Fatalf("state must always serialise: %v", err)
		}
		if n > 0 && st.Size != uint64(len(log)) {
			t.Fatalf("fixture genesis was rejected: size = %d", st.Size)
		}
		if len(st.Rejected) > len(log) {
			t.Fatalf("%d entries produced %d rejections", len(log), len(st.Rejected))
		}
	})
}

// An accepted genesis and fixture prefix precede arbitrary bytes, so state
// exists for a hostile operator to try to corrupt.
func FuzzReplayAfterAValidGenesis(f *testing.F) {
	anchor, entries := replayFuzzCorpus(f)
	for i := 1; i < len(entries); i++ {
		f.Add(uint16(i-1), entries[i])
	}
	f.Fuzz(func(t *testing.T, prefix uint16, raw []byte) {
		n := 1 + int(prefix)%(len(entries)-1)
		log := append(append([][]byte(nil), entries[:n]...), raw)
		st := Replay(anchor, log)
		if st.Size != uint64(len(log)) {
			t.Fatalf("%d entries consumed, size = %d", len(log), st.Size)
		}
		out, err := st.MarshalCanonical()
		if err != nil {
			t.Fatalf("state must always serialise: %v", err)
		}
		if len(out) == 0 {
			t.Fatal("serialised state is empty")
		}
		// active_wg is derived, so it must never disagree with devices.
		for key, id := range st.ActiveWg {
			d, ok := st.Devices[id]
			if !ok || d.WgPk != key || d.Status != "active" {
				t.Fatalf("active_wg[%s] = %q but devices disagrees", key, id)
			}
		}
	})
}

// The ordinary suite must catch missing fuzz fixtures before a fuzz run can skip.
func TestTheReplayFuzzCorpusReachesHandlersAfterGenesis(t *testing.T) {
	anchor, entries := replayFuzzCorpus(t)
	if len(entries) < 3 {
		t.Fatal("the fuzz corpus needs a multi-entry log")
	}
	for i := 1; i <= len(entries); i++ {
		st := Replay(anchor, entries[:i])
		if st.Size != uint64(i) {
			t.Fatalf("fixture prefix %d aborted at genesis: size = %d", i, st.Size)
		}
	}
	st := Replay(anchor, entries)
	if len(st.Devices) == 0 {
		t.Fatal("the fuzz corpus reached no enrollment handler")
	}
}

func replayFuzzCorpus(tb testing.TB) (Anchor, [][]byte) {
	tb.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust.cbor"))
	if err != nil {
		tb.Fatal(err)
	}
	tr, err := trust.Parse(raw)
	if err != nil {
		tb.Fatal(err)
	}
	anchor := Anchor{Net: tr.Net, GenesisHash: tr.GenesisHash}
	root := filepath.Join(vectorRoot(), "log")
	raw, err = os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		tb.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		tb.Fatal(err)
	}
	if len(m.Entries) < 3 {
		tb.Fatal("the fuzz corpus needs genesis and multiple later entries")
	}
	entries := make([][]byte, len(m.Entries))
	for i, e := range m.Entries {
		entries[i], err = os.ReadFile(filepath.Join(root, e.Name+".cbor"))
		if err != nil {
			tb.Fatal(err)
		}
	}
	st := Replay(anchor, entries[:1])
	if st.Size != 1 || len(st.Rejected) != 0 {
		tb.Fatal("the fuzz corpus genesis does not match the trust anchor")
	}
	return anchor, entries
}
