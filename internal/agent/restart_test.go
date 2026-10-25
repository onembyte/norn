package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

// restartable is an owner-mode node over runDir, as `nornd` builds one: the
// run directory is the only thing a process leaves behind for the next one.
func restartable(t *testing.T, logDir, runDir string, device peertable.Device,
	rec *recorder) *Agent {
	t.Helper()
	return rebootable(t, logDir, runDir, "", device, rec)
}

// rebootable is restartable with the state directory apart from the run
// directory, as `nornd` lays them out: a reboot empties the one and not the
// other.
func rebootable(t *testing.T, logDir, runDir, stateDir string, device peertable.Device,
	rec *recorder) *Agent {
	t.Helper()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(logDir), Device: device,
		Mode: reconcile.Owner, RunDir: runDir, StateDir: stateDir, Emit: rec.emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// publishedSize reads the size proven.json says this node last verified.
func publishedSize(t *testing.T, runDir string) int64 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(runDir, proven.FileName))
	if err != nil {
		t.Fatal(err)
	}
	var set proven.Set
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	return set.Checkpoint.Size
}

// F1, and §10's whole reason for a stored checkpoint: a log that has revoked a
// device can serve an earlier head of itself -- correctly signed, correctly
// cosigned, because it *is* that log, earlier -- and a node that compares
// against nothing installs the device again. A node that forgot what it held
// when it restarted is that node, and a restart is something an attacker can
// cause.
func TestARestartDoesNotUndoARevocation(t *testing.T) {
	dir, store, entries := writableLog(t)
	runDir := t.TempDir()
	fake := peertable.NewFake()
	target := keyOfDevice(t, "nas")

	first := restartable(t, dir, runDir, fake, &recorder{})
	appendRevoke(t, store, "nas", uint64(len(entries)))
	if err := first.Once(); err != nil {
		t.Fatal(err)
	}
	if peers, _ := fake.Peers(); holds(peers, target) || len(peers) == 0 {
		t.Fatalf("the revoked log was not enforced to begin with: %+v", peers)
	}
	before, _ := fake.Peers()
	revokedSize := publishedSize(t, runDir)

	// The process goes away. The interface keeps what was last written into
	// it, and the run directory keeps what was last verified.
	older := shorterLog(t, entries)
	rec := &recorder{}
	restarted := restartable(t, older, runDir, fake, rec)

	err := restarted.Once()
	if err == nil {
		t.Fatal("a restarted node accepted an older head of its own log")
	}
	if code, _ := refusal.CodeOf(err); code != refusal.Rollback {
		t.Errorf("refused as %q, want %q: %v", code, refusal.Rollback, err)
	}
	after, _ := fake.Peers()
	if holds(after, target) {
		t.Fatal("a restart un-revoked a device")
	}
	if len(after) != len(before) {
		t.Errorf("the peer table changed on a refused checkpoint: %d -> %d",
			len(before), len(after))
	}
	if got := publishedSize(t, runDir); got != revokedSize {
		t.Errorf("proven.json moved back from %d to %d entries", revokedSize, got)
	}
}

// The restored head is something to compare against, not something to
// enforce. It verified once, in another process, at a witness time this one
// cannot place: a node that installed it before anything verified now would
// reopen peers that an `S_hard` drop had closed, just by being restarted
// during the outage that caused the drop. Until something verifies, the
// interface is left exactly as it is, as it always was.
func TestARestoredHeadIsNotEnforcedUntilSomethingVerifies(t *testing.T) {
	dir, _, _ := writableLog(t)
	runDir := t.TempDir()
	if err := restartable(t, dir, runDir, peertable.NewFake(), &recorder{}).Once(); err != nil {
		t.Fatal(err)
	}

	// A fresh interface, an unreachable log, and the run directory from before.
	fake := peertable.NewFake()
	fake.Inject(rogue(t))
	rec := &recorder{}
	restarted := restartable(t, t.TempDir(), runDir, fake, rec)
	if err := restarted.Once(); err == nil {
		t.Fatal("an unreachable log verified")
	}
	peers, _ := fake.Peers()
	if len(peers) != 1 || peers[0].Key != rogue(t).Key {
		t.Errorf("a restored head was enforced before anything verified: %+v", peers)
	}
	if rec.kinds()[NoStateYet] == 0 {
		t.Errorf("nothing has verified in this process, and the node should say so: %v",
			rec.kinds())
	}
	var fork *logclient.ForkError
	if errors.As(restarted.Once(), &fork) {
		t.Error("an unreachable log is not a fork")
	}
}

// mirrorFile returns one entry bundle of the mirror under runDir, for a test
// to damage.
func mirrorFile(t *testing.T, runDir string) string {
	t.Helper()
	var found string
	root := filepath.Join(runDir, proven.MirrorDir, "tile", "entries")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && found == "" {
			found = path
		}
		return err
	})
	if err != nil || found == "" {
		t.Fatalf("no entry bundle under %s: %v", root, err)
	}
	return found
}

// A mirror that does not verify is not a head this node held -- it is a disk
// fault, a half-finished copy, or another network's log left in a reused run
// directory. It is said out loud, because this restart is then exactly as
// unprotected against a rollback as every restart was before D-069, and the
// node starts as a node with no mirror: it neither trusts it nor refuses to
// run because of it.
func TestAnUnusableMirrorIsReportedAndIgnored(t *testing.T) {
	cases := map[string]struct {
		damage func(t *testing.T, runDir string)
		anchor func(t *testing.T) *trust.Trust
		// verifies is whether the restarted node's first cycle should succeed
		// against the real log: it should whenever the log is this anchor's.
		verifies bool
	}{
		"a flipped byte": {
			damage: func(t *testing.T, runDir string) {
				path := mirrorFile(t, runDir)
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				body[len(body)/2] ^= 0x01
				if err := os.WriteFile(path, body, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			anchor: anchor, verifies: true,
		},
		"a missing bundle": {
			damage: func(t *testing.T, runDir string) {
				if err := os.Remove(mirrorFile(t, runDir)); err != nil {
					t.Fatal(err)
				}
			},
			anchor: anchor, verifies: true,
		},
		"another network's log": {
			damage: func(*testing.T, string) {},
			anchor: freshAnchor, verifies: false,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir, _, _ := writableLog(t)
			runDir := t.TempDir()
			if err := restartable(t, dir, runDir, peertable.NewFake(), &recorder{}).Once(); err != nil {
				t.Fatal(err)
			}
			c.damage(t, runDir)

			rec := &recorder{}
			restarted, err := New(Config{
				Anchor: c.anchor(t), Fetcher: logclient.Dir(dir), Device: peertable.NewFake(),
				Mode: reconcile.Owner, RunDir: runDir, Emit: rec.emit,
				Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
				Mono: func() time.Duration { return 0 },
			})
			if err != nil {
				t.Fatalf("an unusable mirror stopped the node from starting: %v", err)
			}
			if rec.kinds()[MirrorUnusable] != 1 {
				t.Errorf("an unusable mirror should be reported once: %v", rec.kinds())
			}
			if restarted.held() != nil {
				t.Fatal("a mirror that does not verify became the held head")
			}
			if err := restarted.Once(); (err == nil) != c.verifies {
				t.Errorf("first cycle after an ignored mirror: %v", err)
			}
		})
	}
}

// A node's first start has no mirror, and that is not news.
func TestNoMirrorIsNotAnAlarm(t *testing.T) {
	dir, _, _ := writableLog(t)
	rec := &recorder{}
	a := restartable(t, dir, t.TempDir(), peertable.NewFake(), rec)
	if a.held() != nil {
		t.Fatal("a node with an empty run directory holds a head")
	}
	if rec.kinds()[MirrorUnusable] != 0 {
		t.Errorf("a first start raised %s: %v", MirrorUnusable, rec.events)
	}
}

// reHead replaces the log's checkpoint with its current body signed by
// `signer` and cosigned by `witnesses` of the fixture's three -- the same
// log, published under a different key or a different number of witnesses.
func reHead(t *testing.T, dir string, store *tlogstore.Store, signer string, witnesses int) {
	t.Helper()
	doc := anchor(t)
	signed, err := store.SignedCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := note.Split(signed)
	if err != nil {
		t.Fatal(err)
	}
	head, err := note.Sign(body, doc.Origin, fixtureKey(t, signer))
	if err != nil {
		t.Fatal(err)
	}
	head, err = cosign.Append(fixtureWitnesses(t)[:witnesses],
		cosign.At(time.Unix(fixtureCosignedAt, 0)))(head)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
		t.Fatal(err)
	}
}

// D-020 says a node follows a log-key rotation it has replayed, and it does
// -- until it restarts. The trust file still names the old key (the point of
// an in-log rotation is that nobody re-provisions), so a restarted node that
// knew only its trust file could verify neither its own mirror nor the log:
// it never verified again, on any node that restarted after any rotation.
// What it learned from a log it accepted is part of what it held.
func TestARestartAfterALogKeyRotationStillVerifies(t *testing.T) {
	dir, store, _ := writableLog(t)
	runDir := t.TempDir()
	first := restartable(t, dir, runDir, peertable.NewFake(), &recorder{})
	if err := first.Once(); err != nil {
		t.Fatal(err)
	}
	reHead(t, dir, store, "logkey2", 3)
	if err := first.Once(); err != nil {
		t.Fatalf("the running node did not follow the rotation, so nothing here "+
			"is tested: %v", err)
	}

	rec := &recorder{}
	restarted := restartable(t, dir, runDir, peertable.NewFake(), rec)
	if rec.kinds()[MirrorUnusable] != 0 || restarted.held() == nil {
		t.Errorf("the mirror of a log this node accepted under a rotated key was "+
			"not restored: %v", rec.events)
	}
	if err := restarted.Once(); err != nil {
		t.Errorf("a node restarted after a log-key rotation can no longer verify "+
			"its log: %v", err)
	}
}

// The other thing a node learns from its log is the witness policy. The
// fixture's roots raise the quorum to three of three; a restarted node that
// fell back to the trust file's two of three would accept a new head only two
// witnesses vouched for -- the raise would bind only nodes that never
// restart.
func TestARestartKeepsARaisedQuorum(t *testing.T) {
	dir, store, entries := writableLog(t)
	runDir := t.TempDir()
	if err := restartable(t, dir, runDir, peertable.NewFake(), &recorder{}).Once(); err != nil {
		t.Fatal(err)
	}

	// D-082 (1) keeps a held head's acceptance across restart. Grow the log
	// so this tests the learned quorum on a new head, not a re-read.
	appendRevoke(t, store, "nas", uint64(len(entries)))
	reHead(t, dir, store, "logkey", 2)
	restarted := restartable(t, dir, runDir, peertable.NewFake(), &recorder{})
	err := restarted.Once()
	if err == nil {
		t.Fatal("a restarted node accepted a head short of the quorum its roots raised")
	}
	if code, _ := refusal.CodeOf(err); code != refusal.Quorum {
		t.Errorf("refused as %q, want %q: %v", code, refusal.Quorum, err)
	}
}

// SEC-006, and D-069's other half. `nornd`'s run directory is `/run/norn`, a
// tmpfs on every systemd host, so a freeze and a held head kept there survived
// a process restart and vanished at a reboot -- and power-cycling a host is a
// restart an attacker can cause too. A reboot here is a new, empty run
// directory and the same state directory.
func TestAFreezeAndAHeldHeadSurviveAReboot(t *testing.T) {
	t.Run("the held head", func(t *testing.T) {
		dir, store, entries := writableLog(t)
		runDir, stateDir := t.TempDir(), t.TempDir()
		fake := peertable.NewFake()
		first := rebootable(t, dir, runDir, stateDir, fake, &recorder{})
		appendRevoke(t, store, "nas", uint64(len(entries)))
		if err := first.Once(); err != nil {
			t.Fatal(err)
		}
		// What is published stays where readers look for it; what must
		// outlive the boot goes where the boot leaves it.
		if _, err := os.Stat(filepath.Join(runDir, proven.FileName)); err != nil {
			t.Errorf("proven.json is not in the run directory: %v", err)
		}
		if _, err := os.Stat(filepath.Join(stateDir, proven.MirrorDir, "checkpoint")); err != nil {
			t.Errorf("the mirror is not in the state directory: %v", err)
		}
		if _, err := os.Stat(filepath.Join(runDir, proven.MirrorDir)); err == nil {
			t.Error("the mirror is still written to the run directory")
		}

		rebooted := rebootable(t, shorterLog(t, entries), t.TempDir(), stateDir, fake, &recorder{})
		err := rebooted.Once()
		if code, _ := refusal.CodeOf(err); code != refusal.Rollback {
			t.Fatalf("after a reboot an older head was not refused as a rollback: %v", err)
		}
		if peers, _ := fake.Peers(); holds(peers, keyOfDevice(t, "nas")) {
			t.Fatal("a reboot un-revoked a device")
		}
	})
	t.Run("the freeze", func(t *testing.T) {
		real, _, entries := writableLog(t)
		stateDir := t.TempDir()
		first := rebootable(t, real, t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
		if err := first.Once(); err != nil {
			t.Fatal(err)
		}
		first.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, 40))
		_ = first.Once()
		if !first.Frozen() {
			t.Fatal("the fork was not caught, so nothing here is tested")
		}

		rebooted := rebootable(t, real, t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
		if !rebooted.Frozen() {
			t.Fatal("a node that proved its log forked forgot it at a reboot")
		}
	})
}

// A node upgraded in place -- the process restarted, the machine did not --
// still has its freeze and its mirror under the run directory, where the
// version before the split kept them. Upgrading must not be the restart that
// forgets them.
func TestStateLeftInTheRunDirectoryIsStillHonoured(t *testing.T) {
	t.Run("the held head", func(t *testing.T) {
		dir, store, entries := writableLog(t)
		runDir := t.TempDir()
		fake := peertable.NewFake()
		if err := func() error {
			appendRevoke(t, store, "nas", uint64(len(entries)))
			return restartable(t, dir, runDir, fake, &recorder{}).Once()
		}(); err != nil {
			t.Fatal(err)
		}
		upgraded := rebootable(t, shorterLog(t, entries), runDir, t.TempDir(), fake, &recorder{})
		err := upgraded.Once()
		if code, _ := refusal.CodeOf(err); code != refusal.Rollback {
			t.Fatalf("after an upgrade an older head was not refused as a rollback: %v", err)
		}
	})
	t.Run("the freeze", func(t *testing.T) {
		real, _, entries := writableLog(t)
		runDir := t.TempDir()
		first := restartable(t, real, runDir, peertable.NewFake(), &recorder{})
		if err := first.Once(); err != nil {
			t.Fatal(err)
		}
		first.cfg.Fetcher = logclient.Dir(forkedLog(t, entries, 40))
		_ = first.Once()

		upgraded := rebootable(t, real, runDir, t.TempDir(), peertable.NewFake(), &recorder{})
		if !upgraded.Frozen() {
			t.Fatal("an upgrade forgot a freeze the previous version had written")
		}
	})
}
