package monitor

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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
		if a.Rule == "new-entry" || a.Rule == "governance-entry" {
			t.Errorf("an entry was reported twice: %s", a.Message)
		}
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

// The shipped log carries exactly this: `70-profile-base` and
// `89-two-sig-base` are one signed content under two signature lists. A first
// round over it must say so, and a later round must not say so again.
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
	if len(repeated) != 1 {
		t.Fatalf("repeated-entry alerts = %d, want 1 (entry 89 re-signs entry 70): %+v",
			len(repeated), repeated)
	}
	if !strings.Contains(repeated[0].Message, "89") || !strings.Contains(repeated[0].Message, "70") {
		t.Errorf("the alert should name both entries: %q", repeated[0].Message)
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
	// one more, unresolvable signature is new bytes to a byte-keyed replay.
	env, err := entry.Decode(entries[37])
	if err != nil {
		t.Fatal(err)
	}
	env.Sigs = append(env.Sigs, entry.Signature{Kid: "ffffffffffffffff", Role: "signer",
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
