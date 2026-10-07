package monitor

import (
	"strings"
	"testing"
	"time"
)

// `LAB.md` §3's rules table, as code. The table is the specification; these
// tests are it read back.
//
// Two things matter beyond "the right level comes out". A homelab operator has
// to be able to change the thresholds without editing Go, and every alert has
// to arrive with a **sentence a person can act on** -- a monitor that pages at
// three in the morning with `LEVEL=2 CODE=7` has failed at the only job it
// has.

func TestGovernanceEntriesAreTheLoudestThing(t *testing.T) {
	rules := Default()

	for _, kind := range []string{"signer_add", "signer_remove", "root_add",
		"root_remove", "log_key", "policy", "params"} {
		alert, ok := rules.Entry(Entry{Type: kind, Summary: "somebody did something"})
		if !ok {
			t.Fatalf("%s produced no alert", kind)
		}
		if alert.Level != Critical {
			t.Errorf("%s is %s, want critical: governance changes are the loudest "+
				"thing in the system", kind, alert.Level)
		}
	}
}

// "any new entry | info | every entry, always; a homelab has few."
func TestEveryOtherEntryIsStillReported(t *testing.T) {
	rules := Default()

	alert, ok := rules.Entry(Entry{Type: "enroll", Summary: "signer-1 enrolled pi-cam"})
	if !ok {
		t.Fatal("an ordinary entry produced no alert; a homelab wants to see them all")
	}
	if alert.Level != Info {
		t.Errorf("level = %s, want info", alert.Level)
	}
	if !strings.Contains(alert.Message, "pi-cam") {
		t.Errorf("the alert should carry what happened: %q", alert.Message)
	}
}

// Checkpoint age: "warning → critical at 3·S". The escalation is the point --
// a freeze that has gone on three times too long is a different event from one
// that just started.
func TestCheckpointAgeEscalates(t *testing.T) {
	rules := Default()
	staleness := 10 * time.Minute

	for _, tc := range []struct {
		age   time.Duration
		want  Level
		alert bool
	}{
		{5 * time.Minute, Info, false},
		{staleness, Info, false},
		{staleness + time.Second, Warning, true},
		{3 * staleness, Warning, true},
		{3*staleness + time.Second, Critical, true},
	} {
		alert, ok := rules.CheckpointAge("node1", tc.age, staleness)
		if ok != tc.alert {
			t.Errorf("age %v: alerted = %v, want %v", tc.age, ok, tc.alert)
			continue
		}
		if ok && alert.Level != tc.want {
			t.Errorf("age %v: level = %s, want %s", tc.age, alert.Level, tc.want)
		}
		if ok && !strings.Contains(alert.Message, "node1") {
			t.Errorf("the node should be named: %q", alert.Message)
		}
	}
}

// The critical ones, each of which means something is happening now.
func TestTheCriticalRules(t *testing.T) {
	rules := Default()

	for _, kind := range []string{
		"FORK", "UNPROVEN_PEER", "EVICTED_PEER", "CONTROL_PLANE_FIGHT",
	} {
		t.Run(kind, func(t *testing.T) {
			alert, ok := rules.Node("node1", kind, "something happened")
			if !ok {
				t.Fatal("no alert")
			}
			if alert.Level != Critical {
				t.Errorf("level = %s, want critical", alert.Level)
			}
			if !strings.Contains(alert.Message, "node1") {
				t.Errorf("the node should be named: %q", alert.Message)
			}
		})
	}
}

// And the warnings, which are "look at this today" rather than "wake up".
func TestTheWarningRules(t *testing.T) {
	rules := Default()

	cases := map[string]func() (Alert, bool){
		"clock skew":        func() (Alert, bool) { return rules.Node("node2", "CLOCK_SKEW", "two hours out") },
		"rejected entry":    func() (Alert, bool) { return rules.RejectedEntry(7, "unknown-type") },
		"heartbeat missing": func() (Alert, bool) { return rules.Heartbeat("node3", 6*time.Minute) },
		"quorum unreachable": func() (Alert, bool) {
			return rules.WitnessQuorum(5*time.Minute, time.Minute)
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			alert, ok := run()
			if !ok {
				t.Fatal("no alert")
			}
			if alert.Level != Warning {
				t.Errorf("level = %s, want warning", alert.Level)
			}
		})
	}
}

// A node that answered recently is not news.
func TestAHealthyHeartbeatIsSilent(t *testing.T) {
	rules := Default()

	if _, ok := rules.Heartbeat("node3", time.Minute); ok {
		t.Error("a node seen a minute ago was reported as missing")
	}
}

// "nornd down = window becomes ∞ in watchdog" -- the reason a missing
// heartbeat matters has to be in the alert, or an operator files it under
// "probably fine".
func TestAMissingHeartbeatSaysWhyItMatters(t *testing.T) {
	rules := Default()

	alert, _ := rules.Heartbeat("node3", 10*time.Minute)
	if !strings.Contains(alert.Message, "watchdog") {
		t.Errorf("the alert should say what stops happening: %q", alert.Message)
	}
}

// "anchor lag > max_lag | info | advisory by design" -- D-009 again, and the
// monitor must not be the place it quietly becomes load-bearing.
func TestAnchorLagIsOnlyEverInfo(t *testing.T) {
	rules := Default()

	alert, ok := rules.AnchorLag(30 * 24 * time.Hour)
	if !ok {
		t.Fatal("a month of anchor lag should at least be mentioned")
	}
	if alert.Level != Info {
		t.Errorf("level = %s: anchoring is advisory by design (D-009)", alert.Level)
	}
}

// A homelab changes the thresholds without editing Go.
func TestThresholdsAreConfigurable(t *testing.T) {
	rules := Default()
	rules.HeartbeatMissing = time.Hour
	rules.MaxAnchorLag = 365 * 24 * time.Hour

	if _, ok := rules.Heartbeat("node3", 30*time.Minute); ok {
		t.Error("a half-hour gap alerted although the threshold is an hour")
	}
	if _, ok := rules.AnchorLag(30 * 24 * time.Hour); ok {
		t.Error("a month of lag alerted although the threshold is a year")
	}
}

// Every alert carries a rule name, because the gate line is "one notification
// received **per rule**" and nobody can count that without one.
func TestEveryAlertNamesItsRule(t *testing.T) {
	rules := Default()
	alerts := []Alert{
		firstOf(rules.Entry(Entry{Type: "policy", Summary: "changed"})),
		firstOf(rules.Entry(Entry{Type: "enroll", Summary: "added"})),
		firstOf(rules.CheckpointAge("n", time.Hour, time.Minute)),
		firstOf(rules.Node("n", "FORK", "x")),
		firstOf(rules.Heartbeat("n", time.Hour)),
		firstOf(rules.AnchorLag(time.Hour * 24 * 30)),
		firstOf(rules.RejectedEntry(1, "bad-sig")),
		firstOf(rules.WitnessQuorum(time.Hour, time.Minute)),
	}
	seen := map[string]bool{}
	for _, alert := range alerts {
		if alert.Rule == "" {
			t.Errorf("an alert has no rule name: %+v", alert)
		}
		seen[alert.Rule] = true
	}
	if len(seen) != len(alerts) {
		t.Errorf("%d distinct rules for %d alerts; a rule that cannot be told from "+
			"another cannot be counted", len(seen), len(alerts))
	}
}

func firstOf(alert Alert, _ bool) Alert { return alert }

// SEC-001 (D-070): an entry whose signed content already appeared is a
// re-signed copy, and a verifier that does not key duplicates on content
// applies it again -- a revoked device may be back. Nothing in the log says
// so except the monitor.
func TestARepeatedSignedContentIsCritical(t *testing.T) {
	alert, ok := Default().RepeatedEntry(89, 70, "enroll")
	if !ok {
		t.Fatal("no alert")
	}
	if alert.Level != Critical {
		t.Errorf("level = %s, want critical", alert.Level)
	}
	if alert.Rule != "repeated-entry" {
		t.Errorf("rule = %q", alert.Rule)
	}
	for _, want := range []string{"89", "70", "enroll"} {
		if !strings.Contains(alert.Message, want) {
			t.Errorf("the message should carry %q: %q", want, alert.Message)
		}
	}
}
