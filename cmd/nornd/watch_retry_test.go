package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/onembyte/norn/internal/agent"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
)

type retryTick struct {
	delay time.Duration
	tick  chan time.Time
}
type watchLog struct {
	slog.Handler
	records chan slog.Record
}

func (h watchLog) Enabled(context.Context, slog.Level) bool      { return true }
func (h watchLog) Handle(_ context.Context, r slog.Record) error { h.records <- r; return nil }

type watchRun struct {
	cancel  context.CancelFunc
	done    chan error
	ticks   chan retryTick
	records chan slog.Record
}

func startWatchRun(t *testing.T, cycle loopCycle, poll time.Duration) *watchRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &watchRun{cancel: cancel, done: make(chan error, 1), ticks: make(chan retryTick, 16), records: make(chan slog.Record, 100)}
	after := func(d time.Duration) <-chan time.Time {
		tick := make(chan time.Time, 1)
		r.ticks <- retryTick{d, tick}
		return tick
	}
	go func() { r.done <- loopWithRetry(ctx, cycle, poll, slog.New(watchLog{records: r.records}), after) }()
	t.Cleanup(func() { cancel() })
	return r
}
func receiveWatch[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for watch loop")
		var zero T
		return zero
	}
}
func (r *watchRun) warning(t *testing.T, errorText string) {
	t.Helper()
	select {
	case err := <-r.done:
		t.Fatalf("loop exited instead of polling: %v", err)
	case record := <-r.records:
		if record.Level != slog.LevelWarn {
			t.Fatalf("watch failure level = %v", record.Level)
		}
		found := false
		record.Attrs(func(a slog.Attr) bool {
			if a.Key == "error" && strings.Contains(a.Value.String(), errorText) {
				found = true
			}
			return true
		})
		if !found {
			t.Fatalf("warning does not name %q: %v", errorText, record)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch failure was not reported")
	}
}
func (r *watchRun) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	if err := receiveWatch(t, r.done); err != nil {
		t.Fatal(err)
	}
}
func waitInitialWatch(t *testing.T, api *localAPIHandler) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		api.mu.Lock()
		reads := api.reads
		api.mu.Unlock()
		if reads >= 2 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("initial poll did not finish")
		case <-time.After(time.Millisecond):
		}
	}
}
func endWatch(api *localAPIHandler) {
	api.mu.Lock()
	bus := api.bus
	api.bus = make(chan string, 8)
	api.mu.Unlock()
	close(bus)
}
func waitRogue(t *testing.T, r *watchRun, events <-chan agent.Event) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Kind == reconcile.UnprovenPeer && e.Peer.Key == (peertable.Key{44}) {
				return
			}
		case err := <-r.done:
			t.Fatalf("loop exited before rogue detection: %v", err)
		case <-deadline:
			t.Fatal("rogue was not detected")
		}
	}
}
func TestAnEndedWatchWarnsOnceAndTheNextPollStillDetectsARogue(t *testing.T) {
	cycle, api, events := tailscaleCycle(t)
	api.watchRequests = make(chan struct{}, 16)
	r := startWatchRun(t, cycle, 20*time.Millisecond)
	receiveWatch(t, api.watchRequests)
	waitInitialWatch(t, api)
	endWatch(api)
	r.warning(t, "EOF")
	receiveWatch(t, r.ticks)
	api.mu.Lock()
	api.keys = append(api.keys, peertable.Key{44})
	api.mu.Unlock()
	waitRogue(t, r, events)
	r.stop(t)
	for len(r.records) > 0 {
		if record := <-r.records; record.Level == slog.LevelWarn {
			t.Fatal("stream failure warned more than once")
		}
	}
}
func TestAWatchReopensAfterBackoffAndABusEventBeatsThePoll(t *testing.T) {
	cycle, api, events := tailscaleCycle(t)
	api.watchRequests = make(chan struct{}, 16)
	r := startWatchRun(t, cycle, time.Hour)
	receiveWatch(t, api.watchRequests)
	waitInitialWatch(t, api)
	endWatch(api)
	r.warning(t, "EOF")
	tick := receiveWatch(t, r.ticks)
	if tick.delay != watchRetryInitial {
		t.Fatalf("first retry = %v", tick.delay)
	}
	select {
	case <-api.watchRequests:
		t.Fatal("watch retried before backoff")
	default:
	}
	tick.tick <- time.Now()
	receiveWatch(t, api.watchRequests)
	if record := receiveWatch(t, r.records); record.Level != slog.LevelInfo {
		t.Fatalf("recovery level = %v", record.Level)
	}
	api.mu.Lock()
	api.keys = append(api.keys, peertable.Key{44})
	bus := api.bus
	api.mu.Unlock()
	bus <- `{}`
	waitRogue(t, r, events)
	endWatch(api)
	r.warning(t, "EOF")
	if tick := receiveWatch(t, r.ticks); tick.delay != watchRetryInitial {
		t.Fatalf("recovered watch did not reset backoff: %v", tick.delay)
	}
	r.stop(t)
}
func TestCancellingDuringWatchBackoffReturnsPromptly(t *testing.T) {
	cycle, api, _ := tailscaleCycle(t)
	api.watchRequests = make(chan struct{}, 16)
	r := startWatchRun(t, cycle, time.Hour)
	receiveWatch(t, api.watchRequests)
	waitInitialWatch(t, api)
	endWatch(api)
	r.warning(t, "EOF")
	receiveWatch(t, r.ticks)
	r.stop(t)
	r.onlyStoppingLog(t)
}
func TestAnInitialWatchFailurePollsAndRetriesWithCappedBackoff(t *testing.T) {
	cycle, api, events := tailscaleCycle(t)
	api.failWatches = 20
	api.watchRequests = make(chan struct{}, 32)
	r := startWatchRun(t, cycle, 20*time.Millisecond)
	receiveWatch(t, api.watchRequests)
	r.warning(t, "503")
	waitInitialWatch(t, api)
	api.mu.Lock()
	api.keys = append(api.keys, peertable.Key{44})
	api.mu.Unlock()
	waitRogue(t, r, events)
	delay := watchRetryInitial
	for i := 0; i < 11; i++ {
		tick := receiveWatch(t, r.ticks)
		if tick.delay != delay {
			t.Fatalf("retry %d delay = %v, want %v", i, tick.delay, delay)
		}
		select {
		case <-api.watchRequests:
			t.Fatal("watch retried without a backoff tick")
		default:
		}
		tick.tick <- time.Now()
		receiveWatch(t, api.watchRequests)
		delay = min(2*delay, watchRetryMaximum)
	}
	receiveWatch(t, r.ticks)
	r.stop(t)
	r.onlyStoppingLog(t)
}

type pollOnlyCycle struct {
	*agent.Agent
	calls chan struct{}
}

func (c pollOnlyCycle) WatchPeerChanges(ctx context.Context) (<-chan error, error) {
	c.calls <- struct{}{}
	return c.Agent.WatchPeerChanges(ctx)
}
func TestAPollOnlyDeviceStartsNoWatchRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := openTailscale
		openTailscale = func(string) (peertable.Device, error) { return peertable.NewFake(), nil }
		t.Cleanup(func() { openTailscale = previous })
		config := Config{Backend: "tailscale", Trust: filepath.Join(vectors(), "trust.cbor"), Log: filepath.Join(vectors(), "served"), RunDir: t.TempDir(), StateDir: t.TempDir()}
		config.SetGossipPort(0, true)
		cycle, _, err := build(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		calls := make(chan struct{}, 10)
		r := startWatchRun(t, pollOnlyCycle{cycle, calls}, time.Hour)
		receiveWatch(t, calls)
		// Let the nil watch result reach the loop before checking that it schedules nothing.
		synctest.Wait()
		r.stop(t)
		if len(r.ticks) != 0 || len(calls) != 0 {
			t.Fatal("poll-only backend started a watch retry")
		}
		r.onlyStoppingLog(t)
	})
}

func (r *watchRun) onlyStoppingLog(t *testing.T) {
	t.Helper()
	for len(r.records) > 0 {
		if record := <-r.records; record.Message != "nornd stopping" || record.Level != slog.LevelInfo {
			t.Fatalf("unexpected watch log: %v", record)
		}
	}
}

func TestASlowWatchReopenDoesNotBlockPolling(t *testing.T) {
	cycle, api, events := tailscaleCycle(t)
	api.watchRequests = make(chan struct{}, 16)
	r := startWatchRun(t, cycle, 20*time.Millisecond)
	receiveWatch(t, api.watchRequests)
	waitInitialWatch(t, api)
	endWatch(api)
	r.warning(t, "EOF")
	hold := make(chan struct{})
	api.mu.Lock()
	api.holdWatch = hold
	api.mu.Unlock()
	tick := receiveWatch(t, r.ticks)
	tick.tick <- time.Now()
	receiveWatch(t, api.watchRequests)
	api.mu.Lock()
	api.keys = append(api.keys, peertable.Key{44})
	api.mu.Unlock()
	waitRogue(t, r, events)
	r.stop(t)
}

type closedWatchCycle struct{ *agent.Agent }

func (c closedWatchCycle) WatchPeerChanges(context.Context) (<-chan error, error) {
	ch := make(chan error)
	close(ch)
	return ch, nil
}
func TestAClosedWatchWithoutAnErrorFallsBackToPolling(t *testing.T) {
	cycle, api, events := tailscaleCycle(t)
	r := startWatchRun(t, closedWatchCycle{cycle}, 20*time.Millisecond)
	r.warning(t, "closed unexpectedly")
	receiveWatch(t, r.ticks)
	api.mu.Lock()
	api.keys = append(api.keys, peertable.Key{44})
	api.mu.Unlock()
	waitRogue(t, r, events)
	r.stop(t)
}
