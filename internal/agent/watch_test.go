package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
)

type watchedDevice struct {
	*peertable.Fake
	events chan error
	err    error
	ctx    context.Context
}

func (d *watchedDevice) Watch(ctx context.Context) (<-chan error, error) {
	d.ctx = ctx
	return d.events, d.err
}
func TestTheAgentForwardsPeerChangesAndSubscriptionErrors(t *testing.T) {
	device := &watchedDevice{Fake: peertable.NewFake(), events: make(chan error, 1)}
	a := newAgent(t, reconcile.Observe, servedLog(t), device, &recorder{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got, err := a.WatchPeerChanges(ctx)
	if err != nil || got != device.events || device.ctx != ctx {
		t.Fatalf("watch = %v, error = %v; subscription was not forwarded", got, err)
	}
	device.err = errors.New("bus unavailable")
	if _, err := a.WatchPeerChanges(ctx); !errors.Is(err, device.err) {
		t.Fatalf("lost subscription error: %v", err)
	}
	plain := newAgent(t, reconcile.Observe, servedLog(t), peertable.NewFake(), &recorder{})
	if got, err := plain.WatchPeerChanges(ctx); got != nil || err != nil {
		t.Fatalf("poll-only device watch = %v, error = %v", got, err)
	}
}
