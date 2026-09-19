package replay

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/entry"
)

// Replay consumes bytes that an untrusted log operator chose. It must never
// panic on them, and it must always terminate with a state that serialises --
// a verifier that crashes on a malformed log is a denial of service against
// the network it was meant to protect.

func FuzzReplayNeverPanics(f *testing.F) {
	matches, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "log", "*.cbor"))
	for _, path := range matches {
		if raw, err := os.ReadFile(path); err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0xa0})

	anchor := Anchor{Net: make([]byte, 16), GenesisHash: make([]byte, 32)}
	f.Fuzz(func(t *testing.T, raw []byte) {
		st := Replay(anchor, [][]byte{raw})
		if _, err := st.MarshalCanonical(); err != nil {
			t.Fatalf("state must always serialise: %v", err)
		}
		// One entry in, so at most one outcome out.
		if len(st.Rejected) > 1 {
			t.Fatalf("one entry produced %d rejections", len(st.Rejected))
		}
	})
}

// A genesis that is accepted, followed by arbitrary bytes: the path where a
// hostile operator has the most room, since state exists to be corrupted.
func FuzzReplayAfterAValidGenesis(f *testing.F) {
	root := filepath.Join("..", "..", "testdata", "vectors", "log")
	genesis, err := os.ReadFile(filepath.Join(root, "00-genesis.cbor"))
	if err != nil {
		f.Skip("genesis vector not present")
	}
	matches, _ := filepath.Glob(filepath.Join(root, "*.cbor"))
	for _, path := range matches {
		if raw, err := os.ReadFile(path); err == nil {
			f.Add(raw)
		}
	}

	net := make([]byte, 16)
	copy(net, []byte("norn-testnet-001"))
	anchor := Anchor{Net: net, GenesisHash: entry.LeafHash(genesis)}

	f.Fuzz(func(t *testing.T, raw []byte) {
		st := Replay(anchor, [][]byte{genesis, raw})
		if st.Size != 2 {
			t.Fatalf("two entries consumed, size = %d", st.Size)
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
