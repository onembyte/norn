package monitor

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/plainlog"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

// The monitor is an **enrolled peer** (`LAB.md` §3): it reads the log and every
// node through the tunnel, with no extra ports, and never sits on the
// enforcement path. So watching is reading — it verifies what it reads exactly
// as a node does, and the only thing it produces is alerts.
//
// The property that matters most here is the ugly one: a monitor that falls
// over when the thing it is monitoring falls over is worse than no monitor,
// because somebody is relying on it.

func vectors() string { return filepath.Join("..", "..", "testdata", "vectors") }

func anchorOf(t *testing.T) *trust.Trust {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// A first round over the fixture's log reports every entry it finds, in plain
// words, and says nothing alarming about a healthy network.
func TestAFirstRoundReportsTheLogInPlainWords(t *testing.T) {
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }

	alerts := w.Round(logclient.Dir(filepath.Join(vectors(), "served")), nil)

	var entries, criticals int
	var sawDevice bool
	for _, a := range alerts {
		switch a.Level {
		case Info:
			entries++
			if strings.Contains(a.Message, "pi-cam") {
				sawDevice = true
			}
		case Critical:
			criticals++
		}
	}
	if entries == 0 {
		t.Fatal("a first round over a 90-entry log reported no entries")
	}
	if !sawDevice {
		t.Error("entries should be described in plain words, naming the device")
	}
	if criticals != 0 {
		// The fixture has governance entries, so this would fire -- which is
		// itself the point being checked below.
		t.Logf("%d critical alerts, which the fixture's governance entries explain",
			criticals)
	}
}

// A second round over an unchanged log says nothing. A monitor that repeated
// ninety entries every thirty seconds would be turned off within the hour, and
// then it would be monitoring nothing.
func TestAnUnchangedLogIsSilent(t *testing.T) {
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }
	served := logclient.Dir(filepath.Join(vectors(), "served"))

	first := w.Round(served, nil)
	if len(first) == 0 {
		t.Fatal("the first round said nothing at all")
	}
	second := w.Round(served, nil)

	for _, a := range second {
		t.Errorf("an unchanged log emitted a new alert: %+v", a)
	}
}

// The fixture's log contains entries replay refuses, and a log publishing
// those is the operator misbehaving or running something buggy. The monitor
// is the only thing that would ever notice.
func TestEntriesTheLogPublishedAndReplayRefusedAreReported(t *testing.T) {
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }

	alerts := w.Round(logclient.Dir(filepath.Join(vectors(), "served")), nil)

	var rejected int
	for _, a := range alerts {
		if a.Rule == "rejected-entry" {
			rejected++
		}
	}
	if rejected == 0 {
		t.Error("the fixture's log publishes entries replay rejects, and none was " +
			"reported; a log operator publishing garbage would go unmentioned")
	}
}

// Publishing an entry is not applying it. Replay's refusal must be the only
// outcome the operator sees, even when the entry can be described fluently.
func TestARejectedEntryIsNeverDescribedAsDone(t *testing.T) {
	result := verifiedLog(t)
	if len(result.State.Rejected) != 114 {
		t.Fatalf("fixture rejections = %d, want 114", len(result.State.Rejected))
	}
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }
	alerts := w.Round(logclient.Dir(filepath.Join(vectors(), "served")), nil)
	refused := map[uint64]bool{}
	for _, r := range result.State.Rejected {
		refused[r.Index] = true
	}
	applied := map[Alert]int{}
	for index, raw := range result.Served {
		if refused[uint64(index)] {
			continue
		}
		env, err := entry.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		alert, _ := Default().Entry(Entry{Type: env.T, Index: int64(index), Summary: plainlog.Describe(env)})
		applied[alert]++
	}
	for _, alert := range alerts {
		if alert.Rule != "new-entry" && alert.Rule != "governance-entry" {
			continue
		}
		if applied[alert] == 0 {
			t.Fatalf("a rejected entry was described as done: %s", alert.Message)
		}
		applied[alert]--
	}

}

func TestARejectedEntrySaysWhatItWouldHaveDoneAndWhyItWasRefused(t *testing.T) {
	result := verifiedLog(t)
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }
	alerts := w.Round(logclient.Dir(filepath.Join(vectors(), "served")), nil)
	for _, rejected := range result.State.Rejected {
		prefix := fmt.Sprintf("the log published entry %d,", rejected.Index)
		found := false
		for _, alert := range alerts {
			if alert.Rule != "rejected-entry" || !strings.HasPrefix(alert.Message, prefix) {
				continue
			}
			found = true
			for _, want := range []string{"would have", "refused", rejected.Reason} {
				if !strings.Contains(alert.Message, want) {
					t.Fatalf("entry %d alert omits %q: %s", rejected.Index, want, alert.Message)
				}
			}
			env, err := entry.Decode(result.Served[rejected.Index])
			if err == nil && env.T == "enroll" && strings.Contains(plainlog.Describe(env), "enrolled spare") &&
				!strings.Contains(alert.Message, "would have enrolled spare") {
				t.Fatalf("the refused enrolment must name spare: %s", alert.Message)
			}
		}
		if !found {
			t.Fatalf("no refusal alert for entry %d", rejected.Index)
		}
	}
}

// Re-signed copies also raise the separate SEC-001 alarm. Each entry still
// gets exactly one outcome, and those outcomes follow the published log.
func TestAFirstRoundReportsOneOutcomePerEntryInLogOrder(t *testing.T) {
	result := verifiedLog(t)
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }
	var outcomes []Alert
	for _, alert := range w.Round(logclient.Dir(filepath.Join(vectors(), "served")), nil) {
		if alert.Rule == "new-entry" || alert.Rule == "governance-entry" || alert.Rule == "rejected-entry" {
			outcomes = append(outcomes, alert)
		}
	}
	if len(outcomes) != len(result.Served) {
		t.Fatalf("outcome alerts = %d, want %d, one per served entry", len(outcomes), len(result.Served))
	}
	rejected := map[uint64]string{}
	for _, r := range result.State.Rejected {
		rejected[r.Index] = r.Reason
	}
	for index, alert := range outcomes {
		if reason, refused := rejected[uint64(index)]; refused {
			if alert.Rule != "rejected-entry" || !strings.HasPrefix(alert.Message, fmt.Sprintf("the log published entry %d,", index)) ||
				!strings.Contains(alert.Message, reason) {
				t.Fatalf("outcome %d = %+v, want its refusal", index, alert)
			}
		} else {
			env, err := entry.Decode(result.Served[index])
			if err != nil {
				t.Fatal(err)
			}
			want, _ := Default().Entry(Entry{Type: env.T, Index: int64(index), Summary: plainlog.Describe(env)})
			if alert != want {
				t.Fatalf("outcome %d = %+v, want %+v", index, alert, want)
			}
		}
	}
}

// A log that cannot be read is news, not a crash.
func TestAnUnreachableLogIsAnAlertNotAPanic(t *testing.T) {
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }

	alerts := w.Round(logclient.Dir(t.TempDir()), nil)

	if len(alerts) == 0 {
		t.Fatal("an unreadable log produced no alert at all")
	}
	found := false
	for _, a := range alerts {
		if a.Rule == "log-unreadable" && a.Level == Warning {
			found = true
		}
	}
	if !found {
		t.Errorf("alerts = %+v, want one saying the log could not be read", alerts)
	}
}

// Each node is read the same way, and a node serving evidence of a fork is the
// loudest thing the monitor can say.
func TestANodeServingForkEvidenceIsCritical(t *testing.T) {
	served := filepath.Join(vectors(), "served")
	evidence := t.TempDir()
	if err := os.WriteFile(filepath.Join(evidence, "1760000000.evidence"),
		[]byte("evidence bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	node := httptest.NewServer(gossip.Handler(served, evidence))
	t.Cleanup(node.Close)

	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }

	alerts := w.Round(logclient.Dir(served), []Node{{Name: "node2", URL: node.URL}})

	for _, a := range alerts {
		if a.Rule == "fork-evidence" && a.Level == Critical {
			if !strings.Contains(a.Message, "node2") {
				t.Errorf("the node holding it should be named: %q", a.Message)
			}
			return
		}
	}
	t.Errorf("a node serving fork evidence produced no critical alert: %+v", alerts)
}

// A node that does not answer is reported once it has been quiet long enough,
// and not before.
func TestANodeThatStopsAnsweringIsReported(t *testing.T) {
	served := filepath.Join(vectors(), "served")
	var up bool
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		gossip.Handler(served, "").ServeHTTP(w, r)
	}))
	t.Cleanup(node.Close)

	at := time.Unix(fixtureCosigned, 0)
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return at }
	nodes := []Node{{Name: "node3", URL: node.URL}}

	up = true
	w.Round(logclient.Dir(served), nodes)

	// A minute later it is down, which is not yet news.
	up = false
	at = at.Add(time.Minute)
	for _, a := range w.Round(logclient.Dir(served), nodes) {
		if a.Rule == "heartbeat" {
			t.Errorf("a node quiet for a minute was reported: %q", a.Message)
		}
	}

	// Ten minutes later it is.
	at = at.Add(10 * time.Minute)
	found := false
	for _, a := range w.Round(logclient.Dir(served), nodes) {
		if a.Rule == "heartbeat" {
			found = true
		}
	}
	if !found {
		t.Error("a node quiet for eleven minutes was never reported")
	}
}

// Everything down at once is the case a monitor exists for, so it must be the
// case it survives.
func TestEverythingDownStillProducesAlerts(t *testing.T) {
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }

	alerts := w.Round(logclient.Dir(t.TempDir()), []Node{
		{Name: "node1", URL: "http://127.0.0.1:1"},
		{Name: "node2", URL: "http://127.0.0.1:2"},
	})

	if len(alerts) == 0 {
		t.Fatal("a network with nothing running produced no alerts")
	}
}

// fixtureCosigned is the instant the fixture's witnesses cosigned at.
const fixtureCosigned = 1_760_003_600

// Cold-model gate run 8, defect D11. §9.4: a checkpoint is acceptable under
// `norn.trust.log_key` **or** a key a replayed state names — both, not either.
// The monitor is where that combination lives (`norn verify` deliberately
// holds only the trust key, which §9.4 permits for a node that has accepted
// nothing), and nothing exercised it: dropping the anchor key once anything
// was learned passed every test here.
//
// Replacing is the weakening. A monitor that keeps only what the log published
// about itself can be walked off the network by a log that publishes a key and
// then stops signing with the one the operator provisioned.
func TestTheWatcherKeepsTheAnchorKeyAfterLearningOthers(t *testing.T) {
	w := New(&trust.Trust{LogKey: "anchor-key", Origin: "norn/x"}, Rules{})
	w.learned = []string{"published-one", "published-two"}

	keys := w.logKeys()
	if len(keys) != 3 {
		t.Fatalf("logKeys() = %v; want the anchor's and both published", keys)
	}
	var held bool
	for _, k := range keys {
		if k == "anchor-key" {
			held = true
		}
	}
	if !held {
		t.Error("the monitor dropped the anchor's key once it had learned others; " +
			"§9.4 says a checkpoint is acceptable under either, so both are kept")
	}
}

// The shipped log carries six re-signed copies (`bad-copy-*`, D-070): past
// entries under a new signature list, each replay now refuses as a duplicate
// and each the monitor must still point at, because a copy is an attempt. A
// first round over it must say so once per copy, naming the original, and a
// later round must not say so again.
func TestAReSignedCopyInTheLogIsReportedOnce(t *testing.T) {
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }
	served := logclient.Dir(filepath.Join(vectors(), "served"))

	var repeated []Alert
	for _, a := range w.Round(served, nil) {
		if a.Rule == "repeated-entry" {
			repeated = append(repeated, a)
		}
	}
	if len(repeated) != 6 {
		t.Fatalf("repeated-entry alerts = %d, want 6, one per bad-copy entry: %+v",
			len(repeated), repeated)
	}
	for _, original := range []string{"entry 37", "entry 28", "entry 35", "entry 16", "entry 89"} {
		found := false
		for _, a := range repeated {
			if strings.Contains(a.Message, original) {
				found = true
			}
		}
		if !found {
			t.Errorf("no alert names the copied %s", original)
		}
	}
	for _, a := range w.Round(served, nil) {
		if a.Rule == "repeated-entry" {
			t.Fatal("an unchanged log reported the same repeated entry twice")
		}
	}
}

// fixtureSeedKey is one of the fixture's Ed25519 keys by its keys.json name.
func fixtureSeedKey(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Ed25519 map[string]struct{ Seed string } `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(keys.Ed25519[name].Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("no seed for %q", name)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// fixtureLog is the shipped log in a writable store, cosigned exactly as the
// shipped one is so the monitor's verifier accepts it, ready to grow.
func fixtureLog(t *testing.T) (string, *tlogstore.Store, [][]byte) {
	t.Helper()
	doc := anchorOf(t)
	var signers []cosign.Signer
	for _, name := range []string{"pi", "vps", "friend"} {
		signers = append(signers, cosign.Signer{Name: "norn-witness/" + name,
			Key: fixtureSeedKey(t, "witness-"+name)})
	}
	dir := t.TempDir()
	store, err := tlogstore.Open(dir, doc.Origin, fixtureSeedKey(t, "logkey"),
		tlogstore.WithCosigner(tlogstore.CosignerFunc(
			cosign.Append(signers, cosign.At(time.Unix(fixtureCosigned, 0))))))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(vectors(), "log", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Entries []struct{ Name string } `json:"entries"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	var entries [][]byte
	for _, e := range manifest.Entries {
		body, err := os.ReadFile(filepath.Join(vectors(), "log", e.Name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Append(body); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, body)
	}
	return dir, store, entries
}

// A re-signed copy that lands after the monitor has been watching for a
// while is the realistic shape of the attack, and it is only recognisable if
// the monitor remembers what it has already seen.
func TestAReSignedCopyLandingLaterIsStillRecognised(t *testing.T) {
	dir, store, entries := fixtureLog(t)
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }
	w.Round(logclient.Dir(dir), nil) // the whole log, remembered

	// Entry 37 enrolled `spare`, revoked at 39. The same signed content under
	// one more, unresolvable signature is new bytes -- and a different junk
	// kid from the fixture's own copy at 114, or this would be that entry's
	// exact bytes, which the rejected-entry rule reports instead.
	env, err := entry.Decode(entries[37])
	if err != nil {
		t.Fatal(err)
	}
	env.Sigs = append(env.Sigs, entry.Signature{Kid: "fffffffffffffff0", Role: "signer",
		Sig: make([]byte, ed25519.SignatureSize)})
	copy, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(copy); err != nil {
		t.Fatal(err)
	}

	var repeated []Alert
	for _, a := range w.Round(logclient.Dir(dir), nil) {
		if a.Rule == "repeated-entry" {
			repeated = append(repeated, a)
		}
	}
	if len(repeated) != 1 {
		t.Fatalf("repeated-entry alerts = %d, want 1 for the copy of entry 37: %+v",
			len(repeated), repeated)
	}
	if !strings.Contains(repeated[0].Message, "37") ||
		!strings.Contains(repeated[0].Message, formatUint(int64(len(entries)))) {
		t.Errorf("the alert should name the copy and the original: %q", repeated[0].Message)
	}
}

// The detector's branches are signed and cosigned under the fixture anchor.
// Their names are relative to its 40-entry earlier head, so both that head
// and the full served log matter: checking only the latter never compares
// two equal sizes, nor a node ahead of the log.
func comparisonWatcher(t *testing.T, views map[string]string) *Watcher {
	t.Helper()
	w := New(anchorOf(t), Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }
	w.NodeFetcher = func(node Node) logclient.Fetcher {
		return logclient.Dir(views[node.Name])
	}
	return w
}

func detectView(name string) string {
	return filepath.Join(vectors(), "detect", name)
}

func conflictAlerts(alerts []Alert) []Alert {
	var conflicts []Alert
	for _, alert := range alerts {
		if alert.Rule == "conflicting-heads" {
			conflicts = append(conflicts, alert)
		}
	}
	return conflicts
}

// A claim about a fork is only useful if it names the two views and tells
// the operator where independently checkable evidence comes from.
func requireConflict(t *testing.T, alerts []Alert, first, second, firstDir, secondDir string) {
	t.Helper()
	conflicts := conflictAlerts(alerts)
	if len(conflicts) != 1 {
		t.Fatalf("conflicting-heads alerts = %d, want exactly one naming %s and %s", len(conflicts), first, second)
	}
	alert := conflicts[0]
	if alert.Level != Critical {
		t.Errorf("level = %s, want critical", alert.Level)
	}
	for _, want := range []string{first, second, "norn verify-evidence", "never freezes"} {
		if !strings.Contains(alert.Message, want) {
			t.Errorf("the alert should carry %q: %q", want, alert.Message)
		}
	}
	for _, dir := range []string{firstDir, secondDir} {
		result, err := logclient.Verify(logclient.Dir(dir), New(anchorOf(t), Default()).logAnchor())
		if err != nil {
			t.Fatalf("the comparison fixture must fully verify: %v", err)
		}
		want := fmt.Sprintf("%d entries, root %x", result.Checkpoint.Size, result.Checkpoint.Root[:8])
		if !strings.Contains(alert.Message, want) {
			t.Errorf("the alert should identify the verified head %q: %q", want, alert.Message)
		}
	}
}

func TestANodeOnASameSizeForkIsCritical(t *testing.T) {
	logDir, nodeDir := detectView("honest-earlier"), detectView("fork-same-size")
	w := comparisonWatcher(t, map[string]string{"pi": nodeDir})
	requireConflict(t, w.Round(logclient.Dir(logDir), []Node{{Name: "pi"}}),
		"the log", "pi", logDir, nodeDir)
}

func TestANodeOnALongerForkIsCritical(t *testing.T) {
	logDir, nodeDir := detectView("honest-earlier"), detectView("fork-longer")
	w := comparisonWatcher(t, map[string]string{"pi": nodeDir})
	requireConflict(t, w.Round(logclient.Dir(logDir), []Node{{Name: "pi"}}),
		"the log", "pi", logDir, nodeDir)
}

func TestEveryForkedNodeIsComparedWithTheFullLog(t *testing.T) {
	logDir := filepath.Join(vectors(), "served")
	for _, branch := range []string{"fork-same-size", "fork-longer", "fork-shorter"} {
		t.Run(branch, func(t *testing.T) {
			nodeDir := detectView(branch)
			w := comparisonWatcher(t, map[string]string{"pi": nodeDir})
			requireConflict(t, w.Round(logclient.Dir(logDir), []Node{{Name: "pi"}}),
				"the log", "pi", logDir, nodeDir)
		})
	}
}

// A peer may be behind the log or ahead of it while sharing its history.
// Neither direction is evidence of two branches.
func TestAPrefixIsNotReportedAsAConflict(t *testing.T) {
	full, earlier := filepath.Join(vectors(), "served"), detectView("honest-earlier")
	for _, dirs := range [][2]string{{full, earlier}, {earlier, full}} {
		w := comparisonWatcher(t, map[string]string{"pi": dirs[1], "nas": dirs[0]})
		alerts := w.Round(logclient.Dir(dirs[0]), []Node{{Name: "pi"}, {Name: "nas"}})
		if conflicts := conflictAlerts(alerts); len(conflicts) != 0 {
			t.Errorf("a prefix raised a fork alert: %+v", conflicts)
		}
	}
}

func TestTwoNodesOnDifferentBranchesAreComparedWhenTheLogIsUnreachable(t *testing.T) {
	first, second := detectView("honest-earlier"), detectView("fork-longer")
	w := comparisonWatcher(t, map[string]string{"pi": first, "nas": second})
	alerts := w.Round(logclient.Dir(t.TempDir()), []Node{{Name: "pi"}, {Name: "nas"}})
	requireConflict(t, alerts, "pi", "nas", first, second)
}

// Losing a round must not erase the view that made the later change of
// history recognisable. It is the last verified view, not the last answer.
func TestANodeChangingHistoryIsComparedWithItsEarlierView(t *testing.T) {
	for _, tc := range []struct{ first, second string }{
		{detectView("honest-earlier"), detectView("fork-same-size")},
		{detectView("honest-earlier"), detectView("fork-longer")},
		{filepath.Join(vectors(), "served"), detectView("fork-shorter")},
	} {
		t.Run(filepath.Base(tc.second), func(t *testing.T) {
			views := map[string]string{"pi": tc.first}
			w := comparisonWatcher(t, views)
			unreachable := logclient.Dir(t.TempDir())
			nodes := []Node{{Name: "pi"}}
			w.Round(unreachable, nodes)
			views["pi"] = detectView("tampered-current")
			if conflicts := conflictAlerts(w.Round(unreachable, nodes)); len(conflicts) != 0 {
				t.Fatalf("a view that failed verification was compared: %+v", conflicts)
			}
			views["pi"] = tc.second
			requireConflict(t, w.Round(unreachable, nodes), "pi's earlier view", "pi", tc.first, tc.second)
			if conflicts := conflictAlerts(w.Round(unreachable, nodes)); len(conflicts) != 0 {
				t.Errorf("the unchanged pair with an earlier view was repeated: %+v", conflicts)
			}
			views["pi"] = tc.first
			if conflicts := conflictAlerts(w.Round(unreachable, nodes)); len(conflicts) != 0 {
				t.Errorf("reversing the same conflicting heads repeated the pair: %+v", conflicts)
			}
		})
	}
}

func TestAnUnchangedConflictingPairIsSilent(t *testing.T) {
	logDir, nodeDir := detectView("honest-earlier"), detectView("fork-longer")
	w := comparisonWatcher(t, map[string]string{"pi": nodeDir})
	nodes := []Node{{Name: "pi"}}
	requireConflict(t, w.Round(logclient.Dir(logDir), nodes), "the log", "pi", logDir, nodeDir)
	if conflicts := conflictAlerts(w.Round(logclient.Dir(logDir), nodes)); len(conflicts) != 0 {
		t.Errorf("the same conflicting pair was reported twice: %+v", conflicts)
	}
}

// Pair identity includes the sources and the full heads. A second node on
// the same branch is a distinct finding; changing poll order is not.
func TestDistinctSourcesAreReportedOnceRegardlessOfPollOrder(t *testing.T) {
	logDir, nodeDir := detectView("honest-earlier"), detectView("fork-longer")
	w := comparisonWatcher(t, map[string]string{"pi": logDir, "nas": nodeDir, "vps": nodeDir})
	unreachable := logclient.Dir(t.TempDir())
	first := []Node{{Name: "pi"}, {Name: "nas"}, {Name: "vps"}}
	if conflicts := conflictAlerts(w.Round(unreachable, first)); len(conflicts) != 2 {
		t.Fatalf("conflicts = %+v, want one for pi/nas and one for pi/vps", conflicts)
	}
	second := []Node{{Name: "vps"}, {Name: "nas"}, {Name: "pi"}}
	if conflicts := conflictAlerts(w.Round(unreachable, second)); len(conflicts) != 0 {
		t.Errorf("changing poll order repeated the same pairs: %+v", conflicts)
	}
}

func TestAnUnverifiedNodeHeadIsNeverCompared(t *testing.T) {
	w := comparisonWatcher(t, map[string]string{"pi": detectView("tampered-current")})
	if conflicts := conflictAlerts(w.Round(logclient.Dir(filepath.Join(vectors(), "served")),
		[]Node{{Name: "pi"}})); len(conflicts) != 0 {
		t.Errorf("an unverified head raised a fork alert: %+v", conflicts)
	}
}

// Being behind another source is ordinary; going backwards from a node's
// own verified history would undo what it already learned. It is a rollback,
// and must be reported without accusing a consistent log of a fork.
func TestANodeShrinkingItsOwnViewIsReportedWithoutCallingItAFork(t *testing.T) {
	full, earlier := filepath.Join(vectors(), "served"), detectView("honest-earlier")
	views := map[string]string{"pi": full}
	w := comparisonWatcher(t, views)
	unreachable := logclient.Dir(t.TempDir())
	nodes := []Node{{Name: "pi"}}
	w.Round(unreachable, nodes)
	views["pi"] = earlier
	alerts := w.Round(unreachable, nodes)
	if conflicts := conflictAlerts(alerts); len(conflicts) != 0 {
		t.Fatalf("a consistent rollback was called a fork: %+v", conflicts)
	}
	var rollbacks []Alert
	for _, alert := range alerts {
		if alert.Rule == "view-rollback" {
			rollbacks = append(rollbacks, alert)
		}
	}
	if len(rollbacks) != 1 || rollbacks[0].Level != Critical {
		t.Fatalf("rollback alerts = %+v, want one critical alert", rollbacks)
	}
	for _, want := range []string{"pi", "pi's earlier view", "40 entries", "162 entries", "never freezes"} {
		if !strings.Contains(rollbacks[0].Message, want) {
			t.Errorf("the rollback alert should carry %q: %q", want, rollbacks[0].Message)
		}
	}
	for _, alert := range w.Round(unreachable, nodes) {
		if alert.Rule == "view-rollback" || alert.Rule == "conflicting-heads" {
			t.Errorf("the unchanged rollback was reported again: %+v", alert)
		}
	}
	views["pi"] = full
	for _, alert := range w.Round(unreachable, nodes) {
		if alert.Rule == "view-rollback" || alert.Rule == "conflicting-heads" {
			t.Errorf("returning to the earlier history raised an alert: %+v", alert)
		}
	}
}
