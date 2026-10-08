package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/freshness"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
)

// agingNode is an owner-mode node over a state directory whose clock a test
// moves, as agingAgent is -- but restartable, so a second one can be built
// over the same directory after the first has aged.
func agingNode(t *testing.T, logDir, stateDir string, mono *time.Duration,
	hard time.Duration, rec *recorder) (*Agent, *peertable.Fake) {
	t.Helper()
	fake := peertable.NewFake()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(logDir), Device: fake,
		Mode: reconcile.Owner, RunDir: t.TempDir(), StateDir: stateDir,
		Emit: rec.emit, Hard: hard,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(*mono) },
		Mono: func() time.Duration { return *mono },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, fake
}

// D-071 (a). A node's estimate of now was seeded by the first head to verify
// in the process, at age zero, so a node that had called its view `degraded`
// for two hours -- or had dropped every peer past S_hard -- restarted into
// `fresh` on the very same head when the log served it again. A restart is
// something whoever keeps a log stale can also cause, which made S_hard a
// limit a restart lifted.
func TestARestartDoesNotMakeAStaleViewFresh(t *testing.T) {
	for _, c := range []struct {
		hard time.Duration
		want string
	}{
		{0, freshness.Degraded},
		{time.Hour, freshness.HardStale},
	} {
		t.Run(c.want, func(t *testing.T) {
			dir, _, _ := writableLog(t)
			stateDir := t.TempDir()
			var mono time.Duration
			before := &recorder{}
			first, _ := agingNode(t, dir, stateDir, &mono, c.hard, before)
			if err := first.Once(); err != nil {
				t.Fatal(err)
			}
			// Two hours pass with the same head: past the fixture's 900 s
			// staleness, and past the hour S_hard when one is set.
			mono = 2 * time.Hour
			if err := first.Once(); err != nil {
				t.Fatal(err)
			}
			if got := first.Freshness(); got != c.want {
				t.Fatalf("before the restart the view is %q, want %q", got, c.want)
			}
			if before.kinds()[ClockUnusable] != 0 {
				t.Fatal("a first start has no clock file, and that is not an alarm")
			}

			// The process restarts: its monotonic clock begins at zero again,
			// and the log serves the very same head.
			var after time.Duration
			rec := &recorder{}
			restarted, fake := agingNode(t, dir, stateDir, &after, c.hard, rec)
			if err := restarted.Once(); err != nil {
				t.Fatal(err)
			}
			if got := restarted.Freshness(); got != c.want {
				t.Errorf("after the restart the same head is %q, want %q", got, c.want)
			}
			if rec.kinds()[Degraded]+rec.kinds()[HardStale] == 0 {
				t.Errorf("the restarted node said nothing about a view it had already called %s: %v",
					c.want, rec.kinds())
			}
			if peers, _ := fake.Peers(); c.hard > 0 && len(peers) != 0 {
				t.Errorf("a restart reopened %d peers an S_hard drop had closed", len(peers))
			}
		})
	}
}

// The file is a lower bound on now, so it is written as the estimate advances
// and whatever the log is doing -- an outage is exactly when it matters -- but
// not on every cycle: a daemon polling five times a second would otherwise
// turn a quiet night into a disk benchmark.
func TestTheClockIsKeptOnAMinuteCadenceEvenWhileTheLogIsDown(t *testing.T) {
	dir, _, _ := writableLog(t)
	stateDir := t.TempDir()
	var mono time.Duration
	a, _ := agingNode(t, dir, stateDir, &mono, 0, &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, clockFile)
	kept := func() int64 {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		seconds, err := strconv.ParseInt(string(raw[len(clockMagic):len(raw)-1]), 10, 64)
		if err != nil {
			t.Fatalf("clock file %q: %v", raw, err)
		}
		return seconds
	}
	if got := kept(); got != fixtureCosignedAt {
		t.Fatalf("first write holds %d, want the head's quorum time %d", got, fixtureCosignedAt)
	}
	mono = 30 * time.Second
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := kept(); got != fixtureCosignedAt {
		t.Errorf("rewritten after 30 s (%d); the cadence is a minute", got)
	}
	// The log goes away; the estimate still advances, and so must the file.
	a.cfg.Fetcher = logclient.Dir(t.TempDir())
	mono = 2 * time.Hour
	_ = a.Once()
	if got := kept(); got != fixtureCosignedAt+2*3600 {
		t.Errorf("with the log down the file holds %d, want %d", got, fixtureCosignedAt+2*3600)
	}
}

// A clock file that does not parse -- a torn write that durable.WriteFile did
// not make, a different version, a stray file -- is ignored and said out loud.
// Guessing a time from it would be worse than having none: the node then
// starts as a first start does, with no clock until a head verifies.
func TestAnUnreadableClockFileIsReportedAndIgnored(t *testing.T) {
	dir, _, _ := writableLog(t)
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, clockFile), []byte("norn-clock/v1\nyesterday\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mono time.Duration
	rec := &recorder{}
	a, _ := agingNode(t, dir, stateDir, &mono, 0, rec)
	if rec.kinds()[ClockUnusable] != 1 {
		t.Errorf("an unreadable clock file was not reported: %v", rec.kinds())
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := a.Freshness(); got != freshness.Fresh {
		t.Errorf("with no usable clock the first head is age zero, got %q", got)
	}
}
