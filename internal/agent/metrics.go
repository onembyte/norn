package agent

import (
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/metrics"
)

// Metrics reads a completed cycle's observations. A scrape neither asks the
// device nor touches the witness clock, and cannot change an agent decision.
func (a *Agent) Metrics() metrics.Snapshot { return *a.metricsPublished.Load() }

// publishMetrics copies the serial cycle's observations for concurrent readers.
func (a *Agent) publishMetrics() {
	if held := a.held(); held != nil {
		a.metricsWork.CheckpointSize = float64(held.Checkpoint.Size)
	}
	if a.frozen {
		a.metricsWork.State = "fork"
	}
	snapshot := a.metricsWork
	a.metricsPublished.Store(&snapshot)
}

// countAdoption observes an acceptance already made. Neither these counters
// nor the rejected-entry cursor is read by any verification or enforcement path.
// Replay includes the held prefix, so only newly learned indices count again.
func (a *Agent) countAdoption(result *logclient.Result, source string) {
	if source == "peer" {
		a.metricsWork.AdoptedPeer++
	} else {
		a.metricsWork.AdoptedLog++
	}
	for _, rejected := range result.State.Rejected {
		if rejected.Index >= uint64(a.metricsReplayThrough) {
			a.metricsWork.ReplayRejected++
		}
	}
	if result.Checkpoint.Size > a.metricsReplayThrough {
		a.metricsReplayThrough = result.Checkpoint.Size
	}
}
