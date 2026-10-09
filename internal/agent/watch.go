package agent

import (
	"context"

	"github.com/onembyte/norn/internal/peertable"
)

// WatchPeerChanges opens a backend's optional event stream. The daemon uses
// it to wake the same serial cycle that handles polls, so a bus notification
// cannot race a proven-set update or a write by the agent.
func (a *Agent) WatchPeerChanges(ctx context.Context) (<-chan error, error) {
	if source, ok := a.cfg.Device.(peertable.ChangeSource); ok {
		return source.Watch(ctx)
	}
	return nil, nil
}
