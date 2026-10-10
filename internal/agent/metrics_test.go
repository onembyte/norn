package agent

import (
	"bytes"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/metrics"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
)

func metricValue(t *testing.T, a *Agent, name string) float64 {
	t.Helper()
	var b bytes.Buffer
	if err := metrics.Write(&b, a.Metrics()); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(line, name+" ") {
			v, err := strconv.ParseFloat(strings.TrimPrefix(line, name+" "), 64)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
	}
	t.Fatalf("missing sample %s", name)
	return 0
}
func TestMetricsCheckpointSizeFollowsTheHeldCheckpoint(t *testing.T) {
	full, _, entries := writableLog(t)
	a := newAgent(t, reconcile.Observe, shorterLog(t, entries[:20]), peertable.NewFake(), &recorder{})
	// Scrapes read published copies while the serial cycle learns a larger head.
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 3 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = a.Metrics()
				}
			}
		}()
	}
	defer func() { close(stop); readers.Wait() }()
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, "norn_checkpoint_size"); got != 20 {
		t.Fatalf("first size = %g", got)
	}
	a.cfg.Fetcher = logclient.Dir(full)
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, "norn_checkpoint_size"); got != float64(len(entries)) || got <= 20 {
		t.Fatalf("extended size = %g", got)
	}
}
func TestMetricsAgeUsesTheFreshnessClock(t *testing.T) {
	var mono time.Duration
	a, _, _ := agingAgent(t, reconcile.Observe, &mono, time.Hour)
	mono = 16 * time.Minute
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, "norn_checkpoint_age_seconds"); got != a.freshness(a.last).Age.Seconds() || got != 960 {
		t.Fatalf("age = %g", got)
	}
	a.cfg.Now = func() time.Time { return time.Unix(0, 0) }
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, "norn_checkpoint_age_seconds"); got != 960 {
		t.Fatalf("wall clock changed age to %g", got)
	}
}
func TestMetricsStateFollowsFreshnessAndFork(t *testing.T) {
	var mono time.Duration
	a, _, _ := agingAgent(t, reconcile.Observe, &mono, time.Hour)
	for _, step := range []struct {
		at    time.Duration
		state string
	}{{0, "fresh"}, {16 * time.Minute, "degraded"}, {2 * time.Hour, "hard_stale"}} {
		mono = step.at
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
		for _, state := range []string{"fresh", "degraded", "hard_stale", "fork"} {
			want := 0.0
			if state == step.state {
				want = 1
			}
			if got := metricValue(t, a, `norn_state{state="`+state+`"}`); got != want {
				t.Fatalf("%s at %s = %g", state, mono, got)
			}
		}
	}
	_, _, entries := writableLog(t)
	a.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, 40))
	_ = a.Once()
	if got := metricValue(t, a, `norn_state{state="fork"}`); got != 1 {
		t.Fatalf("fork = %g", got)
	}
}

// A transport over a handler uses the existing gossip fixtures without binding
// a socket, which also lets the lane run its race gate in the sandbox.
type metricsPeerTransport struct{ handler http.Handler }

func (p metricsPeerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	p.handler.ServeHTTP(w, r)
	return w.Result(), nil
}
func metricsPeer(t *testing.T, dir string) string {
	t.Helper()
	old := gossip.SetTransport(metricsPeerTransport{gossip.Handler(dir, "")})
	t.Cleanup(func() { gossip.SetTransport(old) })
	return "http://peer.invalid"
}
func TestMetricsPeersPolledCountsOnlyAttemptedPolls(t *testing.T) {
	dir, _, _ := writableLog(t)
	peer := metricsPeer(t, dir)
	a := newAgent(t, reconcile.Observe, dir, peertable.NewFake(), &recorder{})
	a.cfg.Peers = func() []string { return []string{peer} }
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	// The first cycle asks once for a checkpoint and once for evidence.
	if got := metricValue(t, a, "norn_gossip_peers_polled_total"); got != 2 {
		t.Fatalf("polls = %g", got)
	}
	a.uncorroborated = false
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, "norn_gossip_peers_polled_total"); got != 2 {
		t.Fatalf("unasked peers counted: %g", got)
	}
}
func TestMetricsAdoptionsKeepLogAndPeerSeparate(t *testing.T) {
	dir, _, _ := writableLog(t)
	peer := metricsPeer(t, dir)
	a := newAgent(t, reconcile.Observe, dir, peertable.NewFake(), &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, `norn_gossip_adopted_from{source="log"}`); got != 1 {
		t.Fatalf("log = %g", got)
	}
	a.cfg.Fetcher = logclient.Dir(t.TempDir())
	a.cfg.Peers = func() []string { return []string{peer} }
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, `norn_gossip_adopted_from{source="peer"}`); got != 1 {
		t.Fatalf("peer = %g", got)
	}
	if got := metricValue(t, a, `norn_gossip_adopted_from{source="log"}`); got != 1 {
		t.Fatalf("peer counted as log: %g", got)
	}
}
func TestMetricsForkEvidenceCountsProofOnce(t *testing.T) {
	dir, _, entries := writableLog(t)
	a := newAgent(t, reconcile.Observe, dir, peertable.NewFake(), &recorder{})
	a.cfg.StateDir = t.TempDir()
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	a.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, 40))
	_ = a.Once()
	if got := metricValue(t, a, "norn_fork_evidence_total"); got != 1 {
		t.Fatalf("forks = %g", got)
	}
	_ = a.Once()
	if got := metricValue(t, a, "norn_fork_evidence_total"); got != 1 {
		t.Fatalf("freeze counted as new proof: %g", got)
	}

	// A second node learns the same proof through the existing evidence path.
	old := gossip.SetTransport(metricsPeerTransport{gossip.Handler(dir, filepath.Join(a.cfg.StateDir, ForkDir))})
	t.Cleanup(func() { gossip.SetTransport(old) })
	second := newAgent(t, reconcile.Observe, dir, peertable.NewFake(), &recorder{})
	second.cfg.StateDir = t.TempDir()
	second.cfg.Peers = func() []string { return []string{"http://peer.invalid"} }
	_ = second.Once()
	if !second.frozen {
		t.Fatal("fixture did not propagate the fork proof")
	}
	if got := metricValue(t, second, "norn_fork_evidence_total"); got != 1 {
		t.Fatalf("peer proof count = %g", got)
	}
	_ = second.Once()
	if got := metricValue(t, second, "norn_fork_evidence_total"); got != 1 {
		t.Fatalf("peer freeze counted again: %g", got)
	}
}
func TestMetricsReplayRejectedCountsEntriesOnce(t *testing.T) {
	dir, _, entries := writableLog(t)
	a := newAgent(t, reconcile.Observe, shorterLog(t, entries[:1]), peertable.NewFake(), &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	before := metricValue(t, a, "norn_replay_rejected_total")
	a.cfg.Fetcher = logclient.Dir(dir)
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	want := float64(len(a.last.State.Rejected))
	if want <= before {
		t.Fatal("fixture added no rejected entries")
	}
	if got := metricValue(t, a, "norn_replay_rejected_total"); got != want {
		t.Fatalf("rejected = %g, want %g", got, want)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, "norn_replay_rejected_total"); got != want {
		t.Fatalf("repeat counted again: %g", got)
	}
}
func TestMetricsClockSkewFollowsTheExistingMeasurement(t *testing.T) {
	var mono time.Duration
	a, _, _ := agingAgent(t, reconcile.Observe, &mono, 0)
	a.cfg.Now = func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(time.Hour) }
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, "norn_clock_skew_seconds"); got != 3600 {
		t.Fatalf("skew = %g", got)
	}
	a.cfg.Now = func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(-time.Hour) }
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, "norn_clock_skew_seconds"); got != -3600 {
		t.Fatalf("skew = %g", got)
	}
}
func TestMetricsReconcileCountsCompletedAttempts(t *testing.T) {
	fake := peertable.NewFake(rogue(t))
	a := newAgent(t, reconcile.Watchdog, servedLog(t), fake, &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	fake.Inject(rogue(t))
	fake.FailWrite = peertable.ErrDown
	_ = a.Once()
	if got := metricValue(t, a, "norn_reconcile_seconds_count"); got != 2 {
		t.Fatalf("attempts = %g", got)
	}
	if got := metricValue(t, a, "norn_reconcile_seconds_sum"); got <= 0 {
		t.Fatalf("duration = %g", got)
	}
}
func TestMetricsEvictedPeersCountsOnlySuccessfulRemovals(t *testing.T) {
	for _, mode := range []reconcile.Mode{reconcile.Watchdog, reconcile.Owner} {
		fake := peertable.NewFake(rogue(t))
		a := newAgent(t, mode, servedLog(t), fake, &recorder{})
		fake.FailWrite = peertable.ErrDown
		_ = a.Once()
		if got := metricValue(t, a, "norn_evicted_peers_total"); got != 0 {
			t.Fatalf("failed eviction counted: %g", got)
		}
		fake.FailWrite = nil
		if err := a.Once(); err != nil {
			t.Fatal(err)
		}
		if got := metricValue(t, a, "norn_evicted_peers_total"); got != 1 {
			t.Fatalf("%s evictions = %g", mode, got)
		}
	}
}
func TestMetricsUnprovenPeersFollowsTheObservedTable(t *testing.T) {
	fake := peertable.NewFake()
	a := newAgent(t, reconcile.Observe, servedLog(t), fake, &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, "norn_unproven_peers"); got != 0 {
		t.Fatalf("unproven = %g", got)
	}
	fake.Inject(rogue(t))
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, "norn_unproven_peers"); got != 1 {
		t.Fatalf("unproven = %g", got)
	}
	if err := fake.Remove([]peertable.Key{rogue(t).Key}); err != nil {
		t.Fatal(err)
	}
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, a, "norn_unproven_peers"); got != 0 {
		t.Fatalf("gauge accumulated: %g", got)
	}
}
func TestMetricsUnknownAgeAndSkewAreNotInvented(t *testing.T) {
	a := newAgent(t, reconcile.Observe, servedLog(t), peertable.NewFake(), &recorder{})
	for _, name := range []string{"norn_checkpoint_age_seconds", "norn_clock_skew_seconds", "norn_unproven_peers"} {
		if !math.IsNaN(metricValue(t, a, name)) {
			t.Fatalf("%s before observation must be NaN", name)
		}
	}
}
