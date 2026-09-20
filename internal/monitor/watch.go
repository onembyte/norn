package monitor

import (
	"fmt"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/freshness"
	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/plainlog"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

// Node is one nornd the monitor watches, at its tunnel address.
type Node struct {
	Name string
	URL  string
}

// Watcher reads a network and says what it sees.
//
// It verifies everything it reads with the same `logclient.Verify` a node
// runs, under the same anchor -- the monitor is an enrolled peer, not a
// privileged one, and a monitor that believed something a node would refuse
// would be reporting on a different network than the one that exists.
//
// It never enforces and it never freezes. `LAB.md` §3: "It never sits on the
// enforcement path."
type Watcher struct {
	anchor *trust.Trust
	rules  Rules

	// Now is the monitor's clock. It is used for heartbeats and for how long
	// a witness quorum has been unreachable -- both of which are about the
	// monitor's own experience of the network rather than about what the log
	// proves, so the local clock is the right one.
	Now func() time.Time

	// learned are the log keys the roots published, picked up by replaying a
	// log this monitor already accepted (D-020). Kept alongside the trust
	// file's key rather than replacing it: the overlap is what lets a rotation
	// happen without every reader being re-provisioned first.
	learned []string

	// policy is the witness policy the roots have published, if any. It
	// replaces the trust file's rather than joining it (§9.4).
	policy string

	// reported is the log size already described, so an unchanged log is
	// silent. A monitor that repeated ninety entries every thirty seconds
	// would be turned off within the hour, and then it would be monitoring
	// nothing.
	reported int64
	// rejectedSeen counts the rejections already reported, for the same reason.
	rejectedSeen int
	// lastSeen is when each node last answered.
	lastSeen map[string]time.Time
}

// New builds a watcher for a network.
func New(anchor *trust.Trust, rules Rules) *Watcher {
	return &Watcher{anchor: anchor, rules: rules, Now: time.Now,
		lastSeen: map[string]time.Time{}}
}

// Round reads the log and every node once and returns what is worth saying.
//
// Nothing in here returns an error. A monitor that fell over when the thing it
// monitors fell over would be worse than no monitor, because somebody is
// relying on it -- so every failure becomes an alert and the round carries on.
func (w *Watcher) Round(log logclient.Fetcher, nodes []Node) []Alert {
	var alerts []Alert
	result, err := logclient.Verify(log, w.logAnchor())
	if err != nil {
		alerts = append(alerts, Alert{Rule: "log-unreadable", Level: Warning,
			Message: fmt.Sprintf("the log could not be read or did not verify: %v. "+
				"Nodes hold their last good view until it comes back.", err)})
	} else {
		w.learn(result)
		alerts = append(alerts, w.readLog(result)...)
	}
	for _, node := range nodes {
		alerts = append(alerts, w.readNode(node)...)
	}
	return alerts
}

// readLog reports what is new in the log since the last round.
func (w *Watcher) readLog(result *logclient.Result) []Alert {
	var alerts []Alert

	// Every entry, always -- in plain words, because an operator who cannot
	// read it will not read it.
	for index := w.reported; index < int64(len(result.Served)); index++ {
		env, err := entry.Decode(result.Served[index])
		if err != nil {
			continue // replay will have rejected it; reported below
		}
		alert, ok := w.rules.Entry(Entry{Type: env.T, Index: index,
			Summary: plainlog.Describe(env)})
		if ok {
			alerts = append(alerts, alert)
		}
	}
	w.reported = int64(len(result.Served))

	// Entries the log published that every verifier refuses.
	for i := w.rejectedSeen; i < len(result.State.Rejected); i++ {
		rejected := result.State.Rejected[i]
		if alert, ok := w.rules.RejectedEntry(int64(rejected.Index), rejected.Reason); ok {
			alerts = append(alerts, alert)
		}
	}
	w.rejectedSeen = len(result.State.Rejected)

	// How old the log's own head is, judged in witness time.
	if age, ok := w.age(result); ok {
		if alert, ok := w.rules.CheckpointAge("the log", age, w.staleness(result)); ok {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// readNode reads one node's gossip endpoints.
func (w *Watcher) readNode(node Node) []Alert {
	var alerts []Alert
	peer := gossip.Peer(node.URL)

	// Evidence first: it is the loudest thing a node can be holding, and a
	// node that has frozen may well be answering nothing else usefully.
	if raw, err := peer.Fetch("evidence"); err == nil && len(raw) > 0 {
		if alert, ok := w.rules.Node(node.Name, "FORK",
			fmt.Sprintf("%d bytes of evidence, which anyone with the trust file can "+
				"check offline", len(raw))); ok {
			alerts = append(alerts, alert)
		}
	}

	result, err := logclient.Verify(peer, w.logAnchor())
	if err != nil {
		if alert, ok := w.rules.Heartbeat(node.Name, w.quietFor(node.Name)); ok {
			alerts = append(alerts, alert)
		}
		return alerts
	}
	w.lastSeen[node.Name] = w.Now()

	if age, ok := w.age(result); ok {
		if alert, ok := w.rules.CheckpointAge(node.Name, age, w.staleness(result)); ok {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// quietFor is how long a node has been unheard from. A node never yet seen is
// treated as quiet since this round, so a monitor starting up does not accuse
// everybody of being down.
func (w *Watcher) quietFor(name string) time.Duration {
	last, ok := w.lastSeen[name]
	if !ok {
		w.lastSeen[name] = w.Now()
		return 0
	}
	return w.Now().Sub(last)
}

// age is how old a verified head is, in witness time.
//
// The monitor has no monotonic history of its own to measure against -- it is
// a watcher, not a node holding a view -- so it compares the checkpoint's
// witness time with its own clock and says so by only ever producing a
// warning from it.
func (w *Watcher) age(result *logclient.Result) (time.Duration, bool) {
	if result.QuorumTime == nil {
		return 0, false
	}
	return w.Now().Sub(*result.QuorumTime), true
}

// staleness is the network's own S, from the log's params.
func (w *Watcher) staleness(result *logclient.Result) time.Duration {
	return freshness.LimitsFrom(result.State.Params, 0).Staleness
}

// logKeys is the trust file's key plus anything the roots have published that
// this monitor has already replayed.
func (w *Watcher) logKeys() []string {
	return append([]string{w.anchor.LogKey}, w.learned...)
}

// learn records what a replayed state authorises, for the next round: the keys
// the roots published, and the policy if they published one.
func (w *Watcher) learn(result *logclient.Result) {
	w.learned = logclient.KeysFrom(w.anchor.Origin, result.State)
	if published := logclient.PolicyFrom(result.State); published != "" {
		w.policy = published
	}
}

// witnessPolicy is the published policy if the roots have set one, and the
// trust file's otherwise.
func (w *Watcher) witnessPolicy() string {
	if w.policy != "" {
		return w.policy
	}
	return w.anchor.Policy
}

func (w *Watcher) logAnchor() logclient.Anchor {
	return logclient.Anchor{
		Anchor:  replay.Anchor{Net: w.anchor.Net, GenesisHash: w.anchor.GenesisHash},
		LogKeys: w.logKeys(), Origin: w.anchor.Origin, Policy: w.witnessPolicy(),
	}
}
