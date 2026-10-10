// Package metrics writes this node's observations in Prometheus text format.
// These counts prove nothing about a log; only its signed bytes can do that.
package metrics

import (
	"fmt"
	"io"
	"strings"
)

// Snapshot is a copy of observations, never an input to enforcement.
type Snapshot struct {
	CheckpointSize float64
	CheckpointAge  float64
	State          string
	PeersPolled    uint64
	AdoptedLog     uint64
	AdoptedPeer    uint64
	ForkEvidence   uint64
	ReplayRejected uint64
	ClockSkew      float64
	Reconcile      Histogram
	EvictedPeers   uint64
	UnprovenPeers  float64
}

// Histogram counts completed attempts to reconcile, including failed writes.
type Histogram struct {
	Buckets [8]uint64
	Sum     float64
	Count   uint64
}

// ReconcileBounds cover sub-millisecond local work through slow kernel writes.
// The last finite bucket is ten seconds so a stuck interface is distinguishable
// from ordinary work; +Inf still counts every attempt, however long it took.
func ReconcileBounds() [8]float64 { return [8]float64{0.0001, 0.001, 0.01, 0.05, 0.1, 0.5, 1, 10} }

func (h *Histogram) Observe(seconds float64) {
	h.Count++
	h.Sum += seconds
	for i, bound := range ReconcileBounds() {
		if seconds <= bound {
			h.Buckets[i]++
		}
	}
}

// Write emits version 0.0.4, with a declaration before every family's samples.
func Write(w io.Writer, s Snapshot) error {
	var b strings.Builder
	family := func(name, kind, help string) { fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind) }
	sample := func(name string, value any) { fmt.Fprintf(&b, "%s %v\n", name, value) }
	family("norn_checkpoint_size", "gauge", "Size of the checkpoint this node holds; NaN before any is held.")
	sample("norn_checkpoint_size", s.CheckpointSize)
	family("norn_checkpoint_age_seconds", "gauge", "Witness-clock age used by the last freshness calculation; NaN when unknown.")
	sample("norn_checkpoint_age_seconds", s.CheckpointAge)
	family("norn_state", "gauge", "Freshness or fork state; no samples when freshness is unknown.")
	if s.State != "" && s.State != "unknown" {
		for _, state := range []string{"fresh", "degraded", "hard_stale", "fork"} {
			value := 0
			if state == s.State {
				value = 1
			}
			sample("norn_state{state="+quote(state)+"}", value)
		}
	}
	family("norn_gossip_peers_polled_total", "counter", "Peer checkpoint and evidence polls attempted in this process.")
	sample("norn_gossip_peers_polled_total", s.PeersPolled)
	family("norn_gossip_adopted_from", "counter", "Verified checkpoints accepted in this process, including unchanged heads, by source.")
	sample("norn_gossip_adopted_from{source="+quote("log")+"}", s.AdoptedLog)
	sample("norn_gossip_adopted_from{source="+quote("peer")+"}", s.AdoptedPeer)
	family("norn_fork_evidence_total", "counter", "Fork proofs established or checked from peers in this process.")
	sample("norn_fork_evidence_total", s.ForkEvidence)
	family("norn_replay_rejected_total", "counter", "Rejected entries first learned in accepted checkpoints in this process.")
	sample("norn_replay_rejected_total", s.ReplayRejected)
	family("norn_clock_skew_seconds", "gauge", "Signed wall-clock skew last measured against a direct log head; NaN before measurement.")
	sample("norn_clock_skew_seconds", s.ClockSkew)
	family("norn_reconcile_seconds", "histogram", "Time spent applying reconciliation, including failed attempts.")
	for i, bound := range ReconcileBounds() {
		sample(fmt.Sprintf("norn_reconcile_seconds_bucket{le=%s}", quote(fmt.Sprint(bound))), s.Reconcile.Buckets[i])
	}
	sample("norn_reconcile_seconds_bucket{le="+quote("+Inf")+"}", s.Reconcile.Count)
	sample("norn_reconcile_seconds_sum", s.Reconcile.Sum)
	sample("norn_reconcile_seconds_count", s.Reconcile.Count)
	family("norn_evicted_peers_total", "counter", "Peers successfully removed or omitted by an owner replacement in this process.")
	sample("norn_evicted_peers_total", s.EvictedPeers)
	family("norn_unproven_peers", "gauge", "Unproven peers in the last table read for reconciliation; NaN before a read.")
	sample("norn_unproven_peers", s.UnprovenPeers)
	_, err := io.WriteString(w, b.String())
	return err
}

// quote uses only the three label escapes admitted by text exposition.
func quote(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(value) + `"`
}
