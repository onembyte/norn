package mirror

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/tlog"
)

// A power cut between the acceptance record and checkpoint must leave the
// old checkpoint's acceptance available. A record named only "current"
// would overwrite that information one write too soon.
func TestAcceptanceIsDurableBeforeItsCheckpointAndKeepsThePreviousHead(t *testing.T) {
	held := verified(t)
	dir := t.TempDir()
	old := Acceptance{Policy: held.AcceptancePolicy, QuorumTime: held.QuorumTime}
	if err := WriteAccepted(dir, held.Checkpoint, held.SignedCheckpoint, held.Served, old); err != nil {
		t.Fatal(err)
	}
	prior, err := ReadAcceptance(dir, held.Checkpoint)
	if err != nil || prior == nil {
		t.Fatalf("acceptance was not persisted: %v", err)
	}
	entries := append(append([][]byte(nil), held.Served...), []byte("new leaf"))
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	cp := tree.Checkpoint(held.Checkpoint.Origin)
	// This writer test does not judge signatures; the caller already did.
	signed := cp.Marshal() + "\n"
	now := time.Unix(1760003600, 0)
	next := Acceptance{Policy: held.State.Policy, QuorumTime: &now}
	original := writeFile
	t.Cleanup(func() { writeFile = original })
	stop := errors.New("crash before checkpoint")
	writeFile = func(path string, raw []byte, mode os.FileMode) error {
		if filepath.Base(path) == "checkpoint" {
			got, err := ReadAcceptance(dir, cp)
			if err != nil || got == nil || got.Policy != next.Policy || !got.QuorumTime.Equal(now) {
				t.Errorf("checkpoint arrived before its acceptance: %v", err)
			}
			return stop
		}
		return original(path, raw, mode)
	}
	if err := WriteAccepted(dir, cp, signed, entries, next); !errors.Is(err, stop) {
		t.Fatalf("did not reach the checkpoint failure: %v", err)
	}
	got, err := ReadAcceptance(dir, held.Checkpoint)
	if err != nil || got == nil || got.Policy != old.Policy || !got.QuorumTime.Equal(*old.QuorumTime) {
		t.Fatal("interrupted write lost the previous head's acceptance", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil || string(raw) != held.SignedCheckpoint {
		t.Fatal("interrupted write replaced the old checkpoint", err)
	}
	writeFile = original
	if err := WriteAccepted(dir, cp, signed, entries, next); err != nil {
		t.Fatal(err)
	}
	writeFile = func(path string, raw []byte, mode os.FileMode) error {
		t.Errorf("unchanged head rewrote %s", path)
		return nil
	}
	if err := WriteAccepted(dir, cp, signed, entries, next); err != nil {
		t.Fatal(err)
	}
}

// No clock is a value, not an omitted record. Bad metadata must not silently
// turn into the legacy path, which could apply a different policy or T.
func TestAcceptanceDistinguishesNoClockMissingAndMalformedRecords(t *testing.T) {
	held := verified(t)
	dir := t.TempDir()
	got, err := ReadAcceptance(dir, held.Checkpoint)
	if err != nil || got != nil {
		t.Fatal("missing acceptance is the legacy path")
	}
	if err := WriteAccepted(dir, held.Checkpoint, held.SignedCheckpoint, held.Served, Acceptance{Policy: "quorum none\n"}); err != nil {
		t.Fatal(err)
	}
	got, err = ReadAcceptance(dir, held.Checkpoint)
	if err != nil || got == nil || got.QuorumTime != nil {
		t.Fatal("no-clock acceptance did not round trip", err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "acceptance-*.json"))
	if err != nil || len(files) != 1 {
		t.Fatal("missing acceptance file", err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"{", strings.Replace(string(raw), `"version":1`, `"version":2`, 1), strings.Replace(string(raw), `"quorum_time":null`, `"quorum_time":-1`, 1)} {
		if err := os.WriteFile(files[0], []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadAcceptance(dir, held.Checkpoint); err == nil {
			t.Errorf("bad acceptance was treated as usable or absent: %s", bad)
		}
	}
}

// A node accepts a new head every checkpoint interval, a minute on a small
// network, and each has its own record; keeping them all would grow the state
// directory without bound. Once a head's checkpoint is published, only its own
// record is ever read again, so the older ones go.
func TestOnlyTheMirroredHeadKeepsItsAcceptanceRecord(t *testing.T) {
	held := verified(t)
	dir := t.TempDir()
	write := func(entries [][]byte) tlog.Checkpoint {
		t.Helper()
		tree, err := tlog.Build(entries)
		if err != nil {
			t.Fatal(err)
		}
		cp := tree.Checkpoint(held.Checkpoint.Origin)
		// This writer test does not judge signatures; the caller already did.
		if err := WriteAccepted(dir, cp, cp.Marshal()+"\n", entries,
			Acceptance{Policy: held.AcceptancePolicy, QuorumTime: held.QuorumTime}); err != nil {
			t.Fatal(err)
		}
		return cp
	}
	entries := append([][]byte(nil), held.Served...)
	var last tlog.Checkpoint
	for i := 0; i < 3; i++ {
		entries = append(entries, []byte("leaf "+strings.Repeat("x", i+1)))
		last = write(entries)
	}
	records, err := filepath.Glob(filepath.Join(dir, "acceptance-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || filepath.Base(records[0]) != acceptanceName(last) {
		t.Fatalf("acceptance records after three heads = %v, want only the mirrored head's", records)
	}
	if got, err := ReadAcceptance(dir, last); err != nil || got == nil {
		t.Fatal("the mirrored head lost its own record", err)
	}
}
