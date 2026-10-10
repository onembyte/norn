package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/freshness"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/trust"
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

// SEC-028. A head with no quorum time -- a `quorum none` policy, under which
// nobody vouches for any instant -- was aged from the zero time once the
// witness clock had been set by anything else: the clock file (D-071 a) or an
// earlier cosigned head. Two thousand years old, so `degraded`, or past S_hard
// `hard_stale`, and an owner node emptied its table. §15: "A `quorum none`
// policy has no quorum time: freshness is `unknown`, not an assertion of
// recency."
func TestAHeadWithNoQuorumTimeIsUnknownEvenWithAClock(t *testing.T) {
	for _, hard := range []time.Duration{0, time.Hour} {
		dir, _, _ := writableLog(t)
		var mono time.Duration
		a, _ := agingNode(t, dir, t.TempDir(), &mono, hard, &recorder{})
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
		uncosigned := *a.last
		uncosigned.QuorumTime = nil
		if got := a.freshness(&uncosigned); got.State != freshness.Unknown || got.Age != nil {
			t.Errorf("S_hard %s: a head nobody vouched for reads %+v, want unknown with no age", hard, got)
		}
	}
}

// End to end: a `quorum none` node that kept a witness clock from before
// (the clock file outlives a policy change and a restart) must not drop its
// peers for a head that simply has no time.
func TestAQuorumNoneNodeWithAClockFileStillEnforces(t *testing.T) {
	dir, _, _ := writableLog(t)
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, clockFile),
		[]byte(clockMagic+strconv.FormatInt(fixtureCosignedAt, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := quorumNoneAnchor(t)
	fake := peertable.NewFake()
	rec := &recorder{}
	a, err := New(Config{
		Anchor: doc, Fetcher: logclient.Dir(dir), Device: fake,
		// §13.2: an owner node runs on `quorum none` only when configured to.
		Mode: reconcile.Owner, RunDir: t.TempDir(), StateDir: stateDir, Emit: rec.emit,
		Hard: time.Hour, AllowNoQuorum: true,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if peers, _ := fake.Peers(); len(peers) == 0 {
		t.Errorf("a quorum-none node dropped every peer: %v", rec.kinds())
	}
	if rec.kinds()[HardStale] != 0 {
		t.Errorf("a head with no time was called hard-stale: %v", rec.kinds())
	}
	if got := a.Freshness(); got != freshness.Unknown {
		t.Errorf("freshness = %q, want unknown", got)
	}
}

// quorumNoneAnchor is the fixture's trust file with nobody required: the
// witnesses listed and named, as §9.1 asks, and the quorum line `none`.
func quorumNoneAnchor(t *testing.T) *trust.Trust {
	t.Helper()
	doc := *anchor(t)
	var lines []string
	for _, line := range strings.Split(doc.Policy, "\n") {
		if strings.HasPrefix(line, "quorum ") {
			line = "quorum none"
		}
		lines = append(lines, line)
	}
	doc.Policy = strings.Join(lines, "\n")
	return &doc
}

// SEC-033. A node whose view has no age -- `quorum none`, where nobody
// vouches for any instant -- said nothing at all, cycle after cycle: an
// operator could not tell a network that asked for no corroboration from one
// whose witnesses had quietly gone. `unknown` is said out loud, on the same
// cadence `degraded` repeats on, and the peer table is kept.
func TestUnknownFreshnessIsSaidOnACadence(t *testing.T) {
	// A log from before the fixture's `policy` entry (28) and its `log_key`
	// rotation (27): the trust file's `quorum none` is then what every cycle
	// verifies under. The full fixture publishes three of three, which would
	// make the second cycle fresh.
	_, _, entries := writableLog(t)
	dir := shorterLog(t, entries[:20])
	var mono time.Duration
	rec := &recorder{}
	fake := peertable.NewFake()
	a, err := New(Config{
		Anchor: quorumNoneAnchor(t), Fetcher: logclient.Dir(dir), Device: fake,
		// §13.2: an owner node runs on `quorum none` only when configured to.
		Mode: reconcile.Owner, RunDir: t.TempDir(), Emit: rec.emit, AllowNoQuorum: true,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return mono },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		at   time.Duration
		want int
	}{
		{0, 1}, {time.Minute, 1}, {4 * time.Minute, 1},
		{DefaultDegradedAlarmEvery, 2}, {DefaultDegradedAlarmEvery + time.Minute, 2},
		{2 * DefaultDegradedAlarmEvery, 3},
	} {
		mono = step.at
		if err := a.Once(); err != nil {
			t.Fatalf("at %s: %v", step.at, err)
		}
		if got := rec.kinds()[FreshnessUnknown]; got != step.want {
			t.Errorf("at %s: %s alarms = %d, want %d", step.at, FreshnessUnknown, got, step.want)
		}
	}
	if peers, _ := fake.Peers(); len(peers) == 0 {
		t.Error("an unknown view emptied the table")
	}
}
