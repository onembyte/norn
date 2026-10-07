// Package monitor turns what a network is doing into alerts a person can act
// on.
//
// The monitor is an **enrolled peer** (`LAB.md` §3): it sees the log, the
// witnesses and every node through the tunnel, with no extra ports, and it
// never sits on the enforcement path. That last part is what makes the rest
// possible -- it may poll witnesses, hold a receipt inbox and talk to a push
// service, none of which a node deciding peer membership should ever do.
//
// This file is `LAB.md` §3's rules table as code, and the table is the
// specification. Two things matter beyond producing the right level: a homelab
// operator changes the thresholds without editing Go, and every alert carries
// a **sentence a person can act on**. A monitor that pages at three in the
// morning with a code and a number has failed at the only job it has.
package monitor

import (
	"fmt"
	"strings"
	"time"
)

// Level is how loud an alert is.
type Level string

// The three levels `LAB.md` §3 uses.
const (
	// Info is the running commentary a homelab wants: every entry, always.
	Info Level = "info"
	// Warning is "look at this today".
	Warning Level = "warning"
	// Critical is "something is happening now".
	Critical Level = "critical"
)

// Alert is one thing worth saying.
type Alert struct {
	// Rule names which rule fired. The Phase 5 gate asks for "one notification
	// per rule", and nothing can count that without a name.
	Rule string
	// Level is how loud.
	Level Level
	// Message is a sentence, not a code. It is what arrives on a phone.
	Message string
	// Subject is the node, witness or entry it is about, when there is one.
	Subject string
}

// Entry is a log entry the monitor has replayed.
type Entry struct {
	Type    string
	Index   int64
	Summary string
}

// Rules is `LAB.md` §3's table with its thresholds.
type Rules struct {
	// HeartbeatMissing is how long a node may go unheard from. The default is
	// §3's five minutes.
	HeartbeatMissing time.Duration
	// MaxAnchorLag is how far behind an OpenTimestamps anchor may fall before
	// it is worth a line. Advisory by D-009, so this is only ever info.
	MaxAnchorLag time.Duration
	// QuorumUnreachable is how long a witness quorum may be unreachable --
	// §3's 2·T_c, so it is expressed as a multiple of the checkpoint interval.
	QuorumUnreachableIntervals int
	// StaleCritical is the multiple of `staleness` at which a stale checkpoint
	// stops being a warning. §3 says 3·S.
	StaleCritical int
}

// Default is the table as `LAB.md` §3 ships it.
func Default() Rules {
	return Rules{
		HeartbeatMissing:           5 * time.Minute,
		MaxAnchorLag:               7 * 24 * time.Hour,
		QuorumUnreachableIntervals: 2,
		StaleCritical:              3,
	}
}

// governance are the entry types §3 calls "the loudest thing in the system".
//
// They are the ones that change *who may say what*: the signers, the roots,
// the log key, the witness policy and the parameters. Everything else adds or
// removes a device, which matters less than changing who decides.
var governance = map[string]bool{
	"signer_add": true, "signer_remove": true,
	"root_add": true, "root_remove": true,
	"log_key": true, "policy": true, "params": true,
}

// Entry reports a new log entry. Every entry, always: a homelab has few, and
// the one nobody was told about is the one that matters.
func (r Rules) Entry(entry Entry) (Alert, bool) {
	if governance[entry.Type] {
		return Alert{Rule: "governance-entry", Level: Critical, Subject: entry.Type,
			Message: fmt.Sprintf("governance change: %s — %s. This is who may say "+
				"what, so it is worth reading now.", entry.Type, entry.Summary)}, true
	}
	return Alert{Rule: "new-entry", Level: Info, Subject: entry.Type,
		Message: fmt.Sprintf("%s: %s", entry.Type, entry.Summary)}, true
}

// CheckpointAge reports a node whose view has gone stale, escalating at
// StaleCritical × the network's own `staleness`.
func (r Rules) CheckpointAge(node string, age, staleness time.Duration) (Alert, bool) {
	if staleness <= 0 || age <= staleness {
		return Alert{}, false
	}
	level := Warning
	tail := "the log may be quiet, unreachable, or refusing to move."
	if age > time.Duration(r.StaleCritical)*staleness {
		level = Critical
		tail = fmt.Sprintf("that is more than %d× this network's staleness, so it "+
			"is a freeze rather than a hiccup.", r.StaleCritical)
	}
	return Alert{Rule: "checkpoint-age", Level: level, Subject: node,
		Message: fmt.Sprintf("%s is enforcing a view %s old — %s",
			node, age.Round(time.Second), tail)}, true
}

// Node reports an event a node emitted. The mapping is §3's, and the
// distinction it draws is between "somebody is doing something" and "something
// about this machine is off".
func (r Rules) Node(node, kind, detail string) (Alert, bool) {
	switch kind {
	case "FORK":
		return Alert{Rule: "fork-evidence", Level: Critical, Subject: node,
			Message: fmt.Sprintf("%s proved this network's log signed two histories: "+
				"%s. The evidence is checkable offline by anyone with the trust "+
				"file.", node, detail)}, true
	case "UNPROVEN_PEER", "EVICTED_PEER", "CONTROL_PLANE_FIGHT":
		return Alert{Rule: strings.ToLower(strings.ReplaceAll(kind, "_", "-")),
			Level: Critical, Subject: node,
			Message: fmt.Sprintf("%s on %s: %s. Something is putting keys on an "+
				"interface that the log does not prove.", kind, node, detail)}, true
	case "CLOCK_SKEW":
		return Alert{Rule: "clock-skew", Level: Warning, Subject: node,
			Message: fmt.Sprintf("%s's clock disagrees with witness time: %s. Nothing "+
				"it enforces is affected, and the clock should be fixed.",
				node, detail)}, true
	default:
		return Alert{}, false
	}
}

// RejectedEntry reports that the log published something replay refused.
func (r Rules) RejectedEntry(index int64, reason string) (Alert, bool) {
	return Alert{Rule: "rejected-entry", Level: Warning, Subject: reason,
		Message: fmt.Sprintf("the log published entry %d, which every verifier "+
			"rejects (%s). The log operator is misbehaving or running something "+
			"buggy; nothing is at risk, because nobody replayed it.",
			index, reason)}, true
}

// RepeatedEntry reports an entry whose signed content already appeared
// earlier in the log: a re-signed copy. A verifier that counts duplicates by
// bytes applies it again, which can bring a revoked device back or roll a
// policy back (SEC-001, D-070), and nothing but the log's own history shows
// it. Critical, because the thing it may have undone is a revocation.
func (r Rules) RepeatedEntry(index, first int64, entryType string) (Alert, bool) {
	return Alert{Rule: "repeated-entry", Level: Critical, Subject: entryType,
		Message: fmt.Sprintf("the log published entry %d, a %s whose signed content "+
			"first appeared at entry %d under a different signature list. A verifier "+
			"that counts duplicates by bytes applies it again: a revoked device may be "+
			"back, or a policy rolled back. Check what entry %d did, and who submitted "+
			"the copy.", index, entryType, first, first)}, true
}

// Heartbeat reports a node that has not been heard from.
func (r Rules) Heartbeat(node string, since time.Duration) (Alert, bool) {
	if since <= r.HeartbeatMissing {
		return Alert{}, false
	}
	return Alert{Rule: "heartbeat", Level: Warning, Subject: node,
		Message: fmt.Sprintf("%s has not been heard from for %s. A node that is not "+
			"running enforces nothing, and in watchdog mode that makes its eviction "+
			"window unbounded.", node, since.Round(time.Second))}, true
}

// WitnessQuorum reports a quorum that has been unreachable for longer than
// 2·T_c: a liveness problem rather than an attack.
func (r Rules) WitnessQuorum(unreachable, checkpointInterval time.Duration) (Alert, bool) {
	limit := time.Duration(r.QuorumUnreachableIntervals) * checkpointInterval
	if checkpointInterval <= 0 || unreachable <= limit {
		return Alert{}, false
	}
	return Alert{Rule: "witness-quorum", Level: Warning,
		Message: fmt.Sprintf("no quorum of witnesses has been reachable for %s. The "+
			"log can still publish, but nothing it publishes will be accepted until "+
			"they return.", unreachable.Round(time.Second))}, true
}

// AnchorLag reports an OpenTimestamps anchor falling behind.
//
// Info, always. D-009 makes anchoring advisory, and the monitor is exactly
// where that would quietly stop being true: a page about a missing anchor
// would train an operator to treat it as load-bearing.
func (r Rules) AnchorLag(lag time.Duration) (Alert, bool) {
	if lag <= r.MaxAnchorLag {
		return Alert{}, false
	}
	return Alert{Rule: "anchor-lag", Level: Info,
		Message: fmt.Sprintf("the newest OpenTimestamps anchor is %s behind. This is "+
			"advisory by design (D-009) and nothing depends on it.",
			lag.Round(time.Hour))}, true
}
