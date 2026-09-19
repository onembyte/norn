package replay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Written from SPEC.md §5. The manifest is the oracle: every (index, reason)
// must match, and the resulting state must equal state.json byte for byte.

type manifest struct {
	Anchor struct {
		Net         string `json:"net"`
		GenesisHash string `json:"genesis_hash"`
	} `json:"anchor"`
	Entries []struct {
		Index  int    `json:"index"`
		Name   string `json:"name"`
		Reason string `json:"reason"`
	} `json:"entries"`
}

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func loadCase(t *testing.T, dir string) (Anchor, [][]byte, manifest) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	net, err := hex.DecodeString(m.Anchor.Net)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := hex.DecodeString(m.Anchor.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([][]byte, 0, len(m.Entries))
	for _, e := range m.Entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, b)
	}
	return Anchor{Net: net, GenesisHash: genesis}, entries, m
}

func TestEveryOutcomeInTheLogManifestMatches(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "log")
	anchor, entries, m := loadCase(t, dir)
	st := Replay(anchor, entries)

	got := map[int]string{}
	for _, r := range st.Rejected {
		got[int(r.Index)] = r.Reason
	}
	for _, e := range m.Entries {
		want := e.Reason
		if got[e.Index] != want {
			t.Errorf("entry %d (%s): got reason %q, want %q",
				e.Index, e.Name, got[e.Index], want)
		}
	}
	if len(got) != countRejections(m) {
		t.Errorf("produced %d rejections, the manifest expects %d", len(got), countRejections(m))
	}
	if int(st.Size) != len(entries) {
		t.Errorf("size = %d, want %d", st.Size, len(entries))
	}
}

func countRejections(m manifest) int {
	var n int
	for _, e := range m.Entries {
		if e.Reason != "" {
			n++
		}
	}
	return n
}

func TestReplayedStateEqualsStateJSONByteForByte(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	st := Replay(anchor, entries)
	got, err := st.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(vectorRoot(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("replayed state differs from state.json (%d vs %d bytes)", len(got), len(want))
		for i := 0; i < len(got) && i < len(want); i++ {
			if got[i] != want[i] {
				lo := max(0, i-60)
				t.Errorf("first difference at byte %d\n got: %s\nwant: %s",
					i, got[lo:min(len(got), i+60)], want[lo:min(len(want), i+60)])
				break
			}
		}
	}
}

func TestEveryGenesisCaseAbortsAndMatchesItsState(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join(vectorRoot(), "genesis", "*"))
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		anchor, entries, _ := loadCase(t, dir)
		st := Replay(anchor, entries)
		if len(st.Rejected) != 1 || st.Rejected[0].Reason != "bad-genesis" {
			t.Errorf("%s: expected exactly one bad-genesis rejection, got %+v", dir, st.Rejected)
			continue
		}
		if st.Size != 0 {
			t.Errorf("%s: an aborted replay has size 0, got %d", dir, st.Size)
		}
		got, err := st.MarshalCanonical()
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(dir, "state.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: state differs from its state.json", dir)
		}
		checked++
	}
	if checked < 12 {
		t.Errorf("only %d genesis cases checked, expected at least 12", checked)
	}
}

// The guarantee D-043 exists for: verification must be load-bearing.
func TestASignatureBlindReplayDoesNotReproduceTheManifest(t *testing.T) {
	anchor, entries, m := loadCase(t, filepath.Join(vectorRoot(), "log"))
	honest := Replay(anchor, entries)
	blind := replayWith(anchor, entries, func(pk, msg, sig []byte) bool { return true })

	if len(blind.Rejected) == len(honest.Rejected) {
		t.Fatal("stubbing signature verification changed nothing; the suite does not " +
			"distinguish a valid signature from a forged one")
	}
	missed := map[int]string{}
	for _, r := range honest.Rejected {
		missed[int(r.Index)] = r.Reason
	}
	for _, r := range blind.Rejected {
		delete(missed, int(r.Index))
	}
	if len(missed) == 0 {
		t.Error("expected the forged-signature vectors to be admitted by a blind replay")
	}
	for index := range missed {
		var name string
		for _, e := range m.Entries {
			if e.Index == index {
				name = e.Name
			}
		}
		t.Logf("blind replay admits %d (%s)", index, name)
	}
}

func TestEmptyLogYieldsTheZeroState(t *testing.T) {
	st := Replay(Anchor{Net: bytes.Repeat([]byte{1}, 16), GenesisHash: make([]byte, 32)}, nil)
	if st.Size != 0 || len(st.Rejected) != 0 {
		t.Errorf("an empty log has size 0 and no rejections, got size=%d rejected=%v",
			st.Size, st.Rejected)
	}
	if len(st.Devices) != 0 || len(st.Roots) != 0 {
		t.Error("an empty log leaves the zero state")
	}
}
