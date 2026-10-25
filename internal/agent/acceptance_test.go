package agent

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/mirror"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
)

// acceptanceLog builds the reader's P24 from served's 162 entries, rather
// than depending on a probe directory outside the repository. Its witnesses
// sign at the fixture's staggered times, so the two policies give different T.
func acceptanceLog(t *testing.T, entries [][]byte, witnesses int) string {
	t.Helper()
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	cp := tlog.Checkpoint{Origin: anchor(t).Origin, Size: tree.Size(), Root: tree.Head()}
	signed, err := note.Sign(cp.Marshal(), cp.Origin, fixtureKey(t, "logkey"))
	if err != nil {
		t.Fatal(err)
	}
	for i, signer := range fixtureWitnesses(t)[:witnesses] {
		signed, err = cosign.Append([]cosign.Signer{signer}, cosign.At(time.Unix(fixtureCosignedAt+int64(7*i), 0)))(signed)
		if err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	if err := mirror.Write(dir, cp, signed, entries); err != nil {
		t.Fatal(err)
	}
	return dir
}

func lateEntry(t *testing.T) []byte {
	t.Helper()
	key := fixtureKey(t, "sundial")
	wg, err := hex.DecodeString("ae5ee1982d4db333d00110bdccb68b845775e2f0676f154766d092b82eaafb14")
	if err != nil {
		t.Fatal(err)
	}
	expiry := uint64(1760003605)
	req, err := enrollreq.New(anchor(t).Net, "late", key.Public().(ed25519.PublicKey), wg, 1760000000, nil, &expiry)
	if err != nil {
		t.Fatal(err)
	}
	if err := enrollreq.Sign(req, key); err != nil {
		t.Fatal(err)
	}
	raw, err := enrollreq.Encode(req)
	if err != nil {
		t.Fatal(err)
	}
	after := uint64(162)
	env := &entry.Envelope{V: entry.Version, T: "enroll", Net: anchor(t).Net, TS: 1760009000, After: &after, Body: map[string]any{"request": raw}}
	for _, name := range []string{"signer1", "signer3"} {
		if err := entry.Sign(env, fixtureKey(t, name), "signer"); err != nil {
			t.Fatal(err)
		}
	}
	raw, err = entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReadingAHeldHeadAgainDoesNotReadmitAnExpiredDevice(t *testing.T) {
	_, served := heldServed(t)
	entries := append(append([][]byte(nil), served.Served...), lateEntry(t))
	if len(entries) != 163 {
		t.Fatal("P24 needs served's 162 entries plus late")
	}
	dir := acceptanceLog(t, entries, 3)
	for _, full := range []bool{false, true} {
		t.Run(map[bool]string{false: "incremental", true: "full"}[full], func(t *testing.T) {
			a := restartable(t, dir, t.TempDir(), peertable.NewFake(), &recorder{})
			if err := a.Once(); err != nil {
				t.Fatal(err)
			}
			first := a.last
			if first.QuorumTime.Unix() != 1760003607 || first.State.Devices["late"].Expires != 1760003605 || proven.IsProven(first.State.Devices["late"], proven.EvaluationTime(first)) {
				t.Fatal("P24 preconditions do not hold")
			}
			if full {
				a.fullVerifiedSet = false
			}
			if err := a.Once(); err != nil {
				t.Fatal(err)
			}
			if !a.last.QuorumTime.Equal(*first.QuorumTime) {
				t.Errorf("re-read moved T: %d -> %d", first.QuorumTime.Unix(), a.last.QuorumTime.Unix())
			}
			if proven.IsProven(a.last.State.Devices["late"], proven.EvaluationTime(a.last)) {
				t.Error("re-read re-admitted the expired device")
			}
		})
	}
}

func TestReadingAHeldHeadWithFewerWitnessesStillAccepts(t *testing.T) {
	for _, firstSuperseded := range []bool{false, true} {
		t.Run(map[bool]string{false: "served first", true: "superseded first"}[firstSuperseded], func(t *testing.T) {
			dir := filepath.Join(vectors(), "served")
			_, served := heldServed(t)
			overlay := acceptanceLog(t, served.Served, 2)
			// Pin that this construction is the shipped superseded note itself.
			want, err := os.ReadFile(filepath.Join(vectors(), "served-superseded", "checkpoint"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(overlay, "checkpoint"))
			if err != nil || string(got) != string(want) {
				t.Fatal("not the shipped superseded head", err)
			}
			if firstSuperseded {
				dir = overlay
			}
			a := restartable(t, dir, t.TempDir(), peertable.NewFake(), &recorder{})
			if err := a.Once(); err != nil {
				t.Fatal(err)
			}
			first := a.last
			a.cfg.Fetcher = logclient.Dir(overlay)
			if err := a.Once(); err != nil {
				t.Fatalf("same tree under the superseded note: %v", err)
			}
			if !a.last.QuorumTime.Equal(*first.QuorumTime) || a.last.SignedCheckpoint != first.SignedCheckpoint || !reflect.DeepEqual(a.last.Cosignatures, first.Cosignatures) {
				t.Fatal("re-read changed the held acceptance or evidence")
			}
		})
	}
}

func TestARestartKeepsTheHeadsPersistedAcceptance(t *testing.T) {
	stateDir := t.TempDir()
	first := rebootable(t, filepath.Join(vectors(), "served"), t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
	if err := first.Once(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(stateDir, proven.MirrorDir, "acceptance-*.json"))
	if err != nil || len(files) != 1 {
		t.Errorf("the mirror has no persisted acceptance: %v (%v)", files, err)
	}
	restarted := rebootable(t, filepath.Join(vectors(), "detect", "honest-earlier"), t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
	if restarted.restored == nil {
		t.Fatal("restart lost the held head")
	}
	if restarted.restored.AcceptancePolicy != anchor(t).Policy || restarted.restored.QuorumTime.Unix() != 1760003607 {
		t.Errorf("restart lost the acceptance policy or T: policy=%q T=%v", restarted.restored.AcceptancePolicy, restarted.restored.QuorumTime)
	}
	if code, _ := refusal.CodeOf(restarted.Once()); code != refusal.Rollback {
		t.Fatalf("older log after restart = %s, want rollback", code)
	}
}

// Old mirrors carry no acceptance record. The trust-first path remains
// necessary for upgrades, including its retry after a log-key rotation.
func TestAMirrorWithoutAcceptanceKeepsTheLegacyRestorePath(t *testing.T) {
	_, served := heldServed(t)
	for _, head := range []string{"served-superseded", "served-rotated"} {
		t.Run(head, func(t *testing.T) {
			stateDir := t.TempDir()
			raw, err := os.ReadFile(filepath.Join(vectors(), head, "checkpoint"))
			if err != nil {
				t.Fatal(err)
			}
			if err := mirror.Write(filepath.Join(stateDir, proven.MirrorDir), served.Checkpoint, string(raw), served.Served); err != nil {
				t.Fatal(err)
			}
			a := rebootable(t, filepath.Join(vectors(), "served"), t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
			if a.restored != nil && a.restored.AcceptancePolicy == "" {
				t.Error("legacy restore must retain the policy its successful attempt used")
			}
			if a.restored == nil || a.restored.QuorumTime.Unix() != 1760003600 {
				t.Fatalf("legacy %s mirror was not restored under the old trust-first path: %+v", head, a.restored)
			}
		})
	}
}

// A larger head still needs the latest quorum and §10's branch comparison.
// The fork subcase makes skipping that comparison observable independently
// of the raised quorum, with all three witnesses signing the other branch.
func TestANewLargerHeadStillNeedsTheRaisedQuorumAndStoredComparison(t *testing.T) {
	_, served := heldServed(t)
	for _, fork := range []bool{false, true} {
		t.Run(map[bool]string{false: "raised quorum", true: "fork"}[fork], func(t *testing.T) {
			a := restartable(t, filepath.Join(vectors(), "served"), t.TempDir(), peertable.NewFake(), &recorder{})
			if err := a.Once(); err != nil {
				t.Fatal(err)
			}
			if a.last.AcceptancePolicy != anchor(t).Policy {
				t.Error("first head did not retain its acceptance policy")
			}
			entries := append(append([][]byte(nil), served.Served...), lateEntry(t))
			witnesses, want := 2, refusal.Quorum
			if fork {
				entries[40] = lateEntry(t)
				witnesses, want = 3, refusal.Fork
			}
			a.cfg.Fetcher = logclient.Dir(acceptanceLog(t, entries, witnesses))
			if code, _ := refusal.CodeOf(a.Once()); code != want {
				t.Fatalf("larger head = %s, want %s", code, want)
			}
		})
	}
}

// A newly accepted larger head uses the published policy. Trust-first restore
// silently moves this head's T forward, even though it preserves the head.
func TestARestartUsesAcceptanceAfterThePolicyHasChanged(t *testing.T) {
	stateDir := t.TempDir()
	first := rebootable(t, filepath.Join(vectors(), "served"), t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
	if err := first.Once(); err != nil {
		t.Fatal(err)
	}
	entries := append(append([][]byte(nil), first.last.Served...), lateEntry(t))
	first.cfg.Fetcher = logclient.Dir(acceptanceLog(t, entries, 3))
	if err := first.Once(); err != nil {
		t.Fatal(err)
	}
	if first.last.QuorumTime.Unix() != 1760003600 {
		t.Fatal("new head did not use the raised quorum")
	}
	restarted := rebootable(t, filepath.Join(vectors(), "served"), t.TempDir(), stateDir, peertable.NewFake(), &recorder{})
	if restarted.restored == nil {
		t.Fatal("restart lost the head")
	}
	if restarted.restored.QuorumTime.Unix() != 1760003600 {
		t.Errorf("restart moved accepted T from 1760003600 to %d", restarted.restored.QuorumTime.Unix())
	}
	if restarted.restored.AcceptancePolicy != first.last.State.Policy {
		t.Error("restart did not use the persisted acceptance policy")
	}
}
