package logclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlogstore"
)

// The verifier loop of SPEC §10, end to end: take the fixture's own entries,
// write them into a real served tile directory, read them back through the
// same interface a node would use, and require the state that comes out to be
// state.json byte for byte.
//
// Until now replay was fed entries from a list. This is the first test where
// they arrive the way they actually will: as tiles and bundles on a disk
// someone else controls.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

type manifest struct {
	Anchor struct {
		Net         string `json:"net"`
		GenesisHash string `json:"genesis_hash"`
	} `json:"anchor"`
	Entries []struct {
		Name string `json:"name"`
	} `json:"entries"`
}

func loadFixture(t *testing.T) (replay.Anchor, [][]byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	net, _ := hex.DecodeString(m.Anchor.Net)
	genesis, _ := hex.DecodeString(m.Anchor.GenesisHash)
	entries := make([][]byte, 0, len(m.Entries))
	for _, e := range m.Entries {
		b, err := os.ReadFile(filepath.Join(vectorRoot(), "log", e.Name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, b)
	}
	return replay.Anchor{Net: net, GenesisHash: genesis}, entries
}

// servedLog writes the fixture into a tile directory and returns its path.
func servedLog(t *testing.T) (string, replay.Anchor) {
	t.Helper()
	anchor, entries := loadFixture(t)
	dir := t.TempDir()
	store, err := tlogstore.Open(dir, "norn/test")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	return dir, anchor
}

func TestVerifyOverAServedDirectoryReproducesStateJSON(t *testing.T) {
	dir, anchor := servedLog(t)

	result, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	got, err := result.State.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(vectorRoot(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("state from a served log differs from state.json (%d vs %d bytes)",
			len(got), len(want))
	}
	_, entries := loadFixture(t)
	if result.Checkpoint.Size != int64(len(entries)) {
		t.Errorf("checkpoint size %d, want %d", result.Checkpoint.Size, len(entries))
	}
	if int(result.State.Size) != len(entries) {
		t.Errorf("replayed size %d, want %d", result.State.Size, len(entries))
	}
}

func TestVerifyChecksTheHeadAgainstTheEntries(t *testing.T) {
	dir, anchor := servedLog(t)

	// A log operator who serves a checkpoint that does not describe the
	// entries it also serves must be caught -- that is the whole point of the
	// tree head being in the checkpoint.
	cpPath := filepath.Join(dir, "checkpoint")
	raw, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(raw, []byte("\n"))
	lines[2] = []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err := os.WriteFile(cpPath, bytes.Join(lines, []byte("\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Error("a checkpoint whose root does not match the entries must be refused")
	}
}

func TestVerifyRefusesATamperedEntry(t *testing.T) {
	dir, anchor := servedLog(t)

	// Flip one byte inside a served entry bundle. The entries no longer hash
	// to the head the checkpoint advertises, so the verifier must refuse
	// rather than replay whatever it was handed.
	bundle := filepath.Join(dir, "tile", "entries", "000")
	raw, err := os.ReadFile(bundle)
	if err != nil {
		matches, _ := filepath.Glob(filepath.Join(dir, "tile", "entries", "000.p", "*"))
		if len(matches) == 0 {
			t.Fatal("no entry bundle found to tamper with")
		}
		bundle = matches[0]
		if raw, err = os.ReadFile(bundle); err != nil {
			t.Fatal(err)
		}
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(bundle, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Error("a tampered entry bundle must be refused")
	}
}

func TestVerifyRefusesAWrongAnchor(t *testing.T) {
	dir, anchor := servedLog(t)
	anchor.GenesisHash = make([]byte, 32)

	result, err := Verify(Dir(dir), anchor)
	if err != nil {
		return // refusing outright is also correct
	}
	// If it returns a state, that state must be the aborted one -- never a
	// populated state built on a genesis the anchor does not pin.
	if len(result.State.Rejected) != 1 || result.State.Rejected[0].Reason != "bad-genesis" {
		t.Errorf("a wrong anchor must abort, got %+v", result.State.Rejected)
	}
	if len(result.State.Devices) != 0 {
		t.Error("a wrong anchor must not yield devices")
	}
}

func TestVerifyRefusesAMissingBundle(t *testing.T) {
	dir, anchor := servedLog(t)
	_ = os.RemoveAll(filepath.Join(dir, "tile", "entries"))
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Error("a log that advertises entries it cannot serve must be refused")
	}
}

func TestSurvivingARestartStillVerifies(t *testing.T) {
	dir, anchor := servedLog(t)
	before, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}
	// Reopen the store, append nothing, and verify again: a restart must
	// neither lose entries nor reorder them.
	if _, err := tlogstore.Open(dir, "norn/test"); err != nil {
		t.Fatal(err)
	}
	after, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatalf("verify after restart: %v", err)
	}
	if after.Checkpoint != before.Checkpoint {
		t.Errorf("restart changed the checkpoint: %+v -> %+v", before.Checkpoint, after.Checkpoint)
	}
	beforeJSON, _ := before.State.MarshalCanonical()
	afterJSON, _ := after.State.MarshalCanonical()
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Error("restart changed the replayed state")
	}
}
