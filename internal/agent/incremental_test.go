package agent

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
)

// countingLog records every path a log was asked for and answered.
type countingLog struct {
	logclient.Fetcher
	fetched map[string]int
}

func (c *countingLog) Fetch(path string) ([]byte, error) {
	raw, err := c.Fetcher.Fetch(path)
	if err == nil {
		c.fetched[path]++
	}
	return raw, err
}

func (c *countingLog) reset() { c.fetched = map[string]int{} }

func (c *countingLog) paths() string {
	var out []string
	for p := range c.fetched {
		out = append(out, p)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// incrementalNode is an owner-mode node over a counting log, with a clock
// the test moves.
func incrementalNode(t *testing.T, dir, stateDir string, mono *time.Duration, rec *recorder) (*Agent, *countingLog) {
	t.Helper()
	log := &countingLog{Fetcher: logclient.Dir(dir), fetched: map[string]int{}}
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: log, Device: peertable.NewFake(),
		Mode: reconcile.Owner, RunDir: t.TempDir(), StateDir: stateDir, Emit: rec.emit,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0).Add(*mono) },
		Mono: func() time.Duration { return *mono },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, log
}

// H4-c. A node that holds a head verified in this process verifies the next
// one from it: an unchanged log costs the checkpoint, and nothing else is
// asked for. (H3-a's fifty-cycle form of the same property belongs to H3.)
func TestAnUnchangedLogCostsTheCheckpointAlone(t *testing.T) {
	dir, _, _ := writableLog(t)
	var mono time.Duration
	a, log := incrementalNode(t, dir, t.TempDir(), &mono, &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if log.fetched["checkpoint"] != 1 || len(log.fetched) < 3 {
		t.Fatalf("the first cycle should fetch everything: %s", log.paths())
	}
	log.reset()
	mono = time.Second
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if got := log.paths(); got != "checkpoint" {
		t.Errorf("the second cycle over an unchanged log fetched %q; want the checkpoint alone", got)
	}
}

// A head read back from the node's own mirror (D-069) is held, and compared
// against -- but it is not a head verified in this process, and the first
// verification after a restart is in full: nothing on disk is believed
// because this node wrote it.
func TestARestoredHeadIsVerifiedInFullNotFrom(t *testing.T) {
	dir, _, _ := writableLog(t)
	stateDir := t.TempDir()
	var mono time.Duration
	first, _ := incrementalNode(t, dir, stateDir, &mono, &recorder{})
	if err := first.Once(); err != nil {
		t.Fatal(err)
	}
	restarted, log := incrementalNode(t, dir, stateDir, &mono, &recorder{})
	if restarted.restored == nil {
		t.Fatal("nothing was restored; the test needs a held head")
	}
	if err := restarted.Once(); err != nil {
		t.Fatal(err)
	}
	if log.fetched["checkpoint"] != 1 || len(log.fetched) < 3 {
		t.Errorf("a restarted node verified from its restored head: %s", log.paths())
	}
}

// Verifying from a held head does not look below it, so a tile rewritten
// after the head was adopted passes the next cycle -- by design, and said so
// in H4-b. The periodic full verification is what catches it, and this is
// the test that it does.
func TestATileCorruptedAfterAdoptionIsCaughtByThePeriodicFullVerify(t *testing.T) {
	dir, _, _ := writableLog(t)
	var mono time.Duration
	rec := &recorder{}
	a, _ := incrementalNode(t, dir, t.TempDir(), &mono, rec)
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	tile := filepath.Join(dir, filepath.FromSlash(tlog.TilePath(0, 0, int(a.last.Checkpoint.Size))))
	raw, err := os.ReadFile(tile)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0x01
	if err := os.WriteFile(tile, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	mono = time.Second
	if err := a.Once(); err != nil {
		t.Fatalf("the cycle after a rewrite below the held head should verify from it: %v", err)
	}
	if rec.kinds()[VerifyFailed] != 0 {
		t.Fatal("an incremental cycle looked below the held head")
	}

	mono = DefaultFullVerifyEvery + time.Second
	if err := a.Once(); err == nil {
		t.Fatal("the periodic full verification accepted a corrupt tile")
	}
	if rec.kinds()[VerifyFailed] != 1 || rec.kinds()[EnforcingOnStaleState] != 1 {
		t.Errorf("the full verification should refuse and hold the last state: %v", rec.kinds())
	}
}

// The fold resumed by VerifyFrom carries its seen set. A copy of a past entry
// appended after the held head is `dup-entry` under it, exactly as under a
// full replay -- the SEC-001 attack by the incremental door.
func TestACopyOfAPastEntryAppendedAfterTheHeldHeadIsADuplicate(t *testing.T) {
	dir, store, entries := writableLog(t)
	var mono time.Duration
	a, _ := incrementalNode(t, dir, t.TempDir(), &mono, &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	before := len(a.last.State.ActiveWg)
	if _, err := store.Append(entries[37]); err != nil {
		t.Fatal(err)
	}
	mono = time.Second
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	rejected := a.last.State.Rejected
	if len(rejected) == 0 || rejected[len(rejected)-1].Index != uint64(len(entries)) ||
		rejected[len(rejected)-1].Reason != replay.ReasonDupEntry {
		t.Fatalf("the appended copy was not refused as dup-entry: %+v", rejected[len(rejected)-1])
	}
	if len(a.last.State.ActiveWg) != before {
		t.Errorf("the copy changed the active set: %d -> %d", before, len(a.last.State.ActiveWg))
	}
}

// H3-a. Fifty cycles over an unchanged log are fifty checkpoint requests and
// nothing else: no bundle, no tile. Before H4 every cycle re-fetched and
// replayed the whole log, which at ten thousand entries and fifty nodes was
// a self-inflicted denial of service (review F3a).
func TestFiftyCyclesOverAnUnchangedLogFetchOnlyTheCheckpoint(t *testing.T) {
	dir, _, _ := writableLog(t)
	var mono time.Duration
	a, log := incrementalNode(t, dir, t.TempDir(), &mono, &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	log.reset()
	for i := 1; i <= 50; i++ {
		mono = time.Duration(i) * time.Second // well inside FullVerifyEvery
		if err := a.Once(); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
	}
	if log.fetched["checkpoint"] != 50 {
		t.Errorf("checkpoint fetched %d times in 50 cycles", log.fetched["checkpoint"])
	}
	for path, n := range log.fetched {
		if strings.HasPrefix(path, "tile/") {
			t.Errorf("%s fetched %d times over an unchanged log", path, n)
		}
	}
}

// H3-b. When the checkpoint changes, the next cycle verifies and adopts the
// new head -- and fetches only what grew.
func TestAChangedCheckpointIsAdoptedNextCycle(t *testing.T) {
	dir, store, entries := writableLog(t)
	var mono time.Duration
	a, log := incrementalNode(t, dir, t.TempDir(), &mono, &recorder{})
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	before := a.last.Checkpoint
	appendRevoke(t, store, "nas", uint64(len(entries)))
	log.reset()
	mono = time.Second
	if err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if a.last.Checkpoint.Size != before.Size+1 || a.last.Checkpoint.Root == before.Root {
		t.Fatalf("the grown head was not adopted: %d -> %d", before.Size, a.last.Checkpoint.Size)
	}
	if a.last.State.Devices["nas"].Status == "active" {
		t.Error("the appended revocation did not take effect")
	}
	want := map[string]bool{"checkpoint": true,
		tlog.EntryBundlePath(0, int(a.last.Checkpoint.Size)): true,
		tlog.TilePath(0, 0, int(a.last.Checkpoint.Size)):     true}
	for path := range log.fetched {
		if !want[path] {
			t.Errorf("%s fetched for a one-entry growth", path)
		}
	}
	for path := range want {
		if log.fetched[path] == 0 {
			t.Errorf("%s not fetched for a one-entry growth", path)
		}
	}
}
