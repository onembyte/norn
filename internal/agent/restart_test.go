package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/refusal"
)

// restartable is an owner-mode node over runDir, as `nornd` builds one: the
// run directory is the only thing a process leaves behind for the next one.
func restartable(t *testing.T, logDir, runDir string, device peertable.Device,
	rec *recorder) *Agent {
	t.Helper()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(logDir), Device: device,
		Mode: reconcile.Owner, RunDir: runDir, Emit: rec.emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// publishedSize reads the size proven.json says this node last verified.
func publishedSize(t *testing.T, runDir string) int64 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(runDir, proven.FileName))
	if err != nil {
		t.Fatal(err)
	}
	var set proven.Set
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	return set.Checkpoint.Size
}

// F1, and §10's whole reason for a stored checkpoint: a log that has revoked a
// device can serve an earlier head of itself -- correctly signed, correctly
// cosigned, because it *is* that log, earlier -- and a node that compares
// against nothing installs the device again. A node that forgot what it held
// when it restarted is that node, and a restart is something an attacker can
// cause.
func TestARestartDoesNotUndoARevocation(t *testing.T) {
	dir, store, entries := writableLog(t)
	runDir := t.TempDir()
	fake := peertable.NewFake()
	target := keyOfDevice(t, "nas")

	first := restartable(t, dir, runDir, fake, &recorder{})
	appendRevoke(t, store, "nas", uint64(len(entries)))
	if err := first.Once(); err != nil {
		t.Fatal(err)
	}
	if peers, _ := fake.Peers(); holds(peers, target) || len(peers) == 0 {
		t.Fatalf("the revoked log was not enforced to begin with: %+v", peers)
	}
	before, _ := fake.Peers()
	revokedSize := publishedSize(t, runDir)

	// The process goes away. The interface keeps what was last written into
	// it, and the run directory keeps what was last verified.
	older := shorterLog(t, entries)
	rec := &recorder{}
	restarted := restartable(t, older, runDir, fake, rec)

	err := restarted.Once()
	if err == nil {
		t.Fatal("a restarted node accepted an older head of its own log")
	}
	if code, _ := refusal.CodeOf(err); code != refusal.Rollback {
		t.Errorf("refused as %q, want %q: %v", code, refusal.Rollback, err)
	}
	after, _ := fake.Peers()
	if holds(after, target) {
		t.Fatal("a restart un-revoked a device")
	}
	if len(after) != len(before) {
		t.Errorf("the peer table changed on a refused checkpoint: %d -> %d",
			len(before), len(after))
	}
	if got := publishedSize(t, runDir); got != revokedSize {
		t.Errorf("proven.json moved back from %d to %d entries", revokedSize, got)
	}
}

// The restored head is something to compare against, not something to
// enforce. It verified once, in another process, at a witness time this one
// cannot place: a node that installed it before anything verified now would
// reopen peers that an `S_hard` drop had closed, just by being restarted
// during the outage that caused the drop. Until something verifies, the
// interface is left exactly as it is, as it always was.
func TestARestoredHeadIsNotEnforcedUntilSomethingVerifies(t *testing.T) {
	dir, _, _ := writableLog(t)
	runDir := t.TempDir()
	if err := restartable(t, dir, runDir, peertable.NewFake(), &recorder{}).Once(); err != nil {
		t.Fatal(err)
	}

	// A fresh interface, an unreachable log, and the run directory from before.
	fake := peertable.NewFake()
	fake.Inject(rogue(t))
	rec := &recorder{}
	restarted := restartable(t, t.TempDir(), runDir, fake, rec)
	if err := restarted.Once(); err == nil {
		t.Fatal("an unreachable log verified")
	}
	peers, _ := fake.Peers()
	if len(peers) != 1 || peers[0].Key != rogue(t).Key {
		t.Errorf("a restored head was enforced before anything verified: %+v", peers)
	}
	if rec.kinds()[NoStateYet] == 0 {
		t.Errorf("nothing has verified in this process, and the node should say so: %v",
			rec.kinds())
	}
	var fork *logclient.ForkError
	if errors.As(restarted.Once(), &fork) {
		t.Error("an unreachable log is not a fork")
	}
}
