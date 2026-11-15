package agent

import (
	"testing"
	"time"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
)

// U1 and the NAS lab (G22) both showed it: with the log unreachable, a node
// asks its peers every poll -- 200 ms in `nornd` -- takes back the head it
// already holds, and said ADOPTED_FROM_PEER every time, about 8,700 lines a
// half hour on each node. The alarm exists because the log being unreachable
// is news; the same head from the same outage five times a second is not.
// It now follows the cadence NO_QUORUM and DEGRADED already have: said on
// entering the condition, again when the adopted head changes, and otherwise
// every DegradedAlarmEvery; a cycle in which the log answers ends it.
func TestAdoptingFromAPeerIsSaidOncePerHeadAndThenOnTheAlarmCadence(t *testing.T) {
	full, store, entries := writableLog(t)
	peerURL, _ := peerServing(t, full)

	var mono time.Duration
	rec := &recorder{}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(t.TempDir()), // an empty, dead "log"
		Device: peertable.NewFake(), Mode: reconcile.Owner, Emit: rec.emit,
		Now:   func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono:  func() time.Duration { return mono },
		Peers: func() []string { return []string{peerURL} },
	})
	if err != nil {
		t.Fatal(err)
	}
	adopted := func() int { return rec.kinds()[AdoptedFromPeer] }
	cycle := func(n int) {
		t.Helper()
		for range n {
			if err := a.Once(); err != nil {
				t.Fatalf("a node with a dead log and a healthy peer should carry on: %v", err)
			}
			mono += 200 * time.Millisecond
		}
	}

	// An outage of a minute at nornd's poll: one line, not three hundred.
	cycle(300)
	if got := adopted(); got != 1 {
		t.Fatalf("the same peer head over one outage was said %d times; want once", got)
	}

	// The alarm cadence still repeats it while the outage lasts.
	mono += a.cfg.DegradedAlarmEvery
	cycle(1)
	if got := adopted(); got != 2 {
		t.Fatalf("after DegradedAlarmEvery the outage should be said again: %d", got)
	}

	// A new head from a peer is news, whenever it comes.
	if _, err := store.Append(entries[1]); err != nil {
		t.Fatal(err)
	}
	cycle(1)
	if got := adopted(); got != 3 {
		t.Fatalf("a larger head taken from a peer should be said at once: %d", got)
	}
	cycle(20)
	if got := adopted(); got != 3 {
		t.Fatalf("that head, taken again, should not be said again: %d", got)
	}

	// The log answers: the condition ends. When it goes again, that is said
	// at once, not at the next cadence.
	a.cfg.Fetcher = logclient.Dir(full)
	cycle(3)
	if got := adopted(); got != 3 {
		t.Fatalf("a cycle the log answered adopted from a peer: %d", got)
	}
	a.cfg.Fetcher = logclient.Dir(t.TempDir())
	cycle(1)
	if got := adopted(); got != 4 {
		t.Fatalf("a new outage should be said at once: %d", got)
	}
}
