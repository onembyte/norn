package monitor

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/replay"
)

// D-078 (1). When the first appearance of a signed content was refused -- a
// copy with its signatures stripped -- the genuine entry after it applies, and
// the copy was an attempt to cancel it. The alert says so, rather than that a
// verifier may have applied something twice.
func TestARepeatedContentAfterARefusedCopyIsReportedAsAnAttempt(t *testing.T) {
	alert, ok := Default().RepeatedEntry(163, 162, "revoke", true)
	if !ok || alert.Level != Critical || alert.Rule != "repeated-entry" {
		t.Fatalf("got %+v, %v", alert, ok)
	}
	for _, want := range []string{"163", "162", "revoke", "refused", "judged on its own"} {
		if !strings.Contains(alert.Message, want) {
			t.Errorf("the message should carry %q: %q", want, alert.Message)
		}
	}
	applied, _ := Default().RepeatedEntry(89, 70, "enroll", false)
	if strings.Contains(applied.Message, "judged on its own") {
		t.Errorf("a copy of an applied entry is not an attempt: %q", applied.Message)
	}
}

// The watcher tells the two apart from replay's own verdict on the first
// appearance: the printer's revoke stripped of its signatures lands first and
// is refused, then the genuine revoke lands and applies.
func TestTheWatcherReportsAStrippedCopyBeforeTheGenuineEntryAsAnAttempt(t *testing.T) {
	dir, store, entries := fixtureLog(t)
	doc := anchorOf(t)
	w := New(doc, Default())
	w.Now = func() time.Time { return time.Unix(fixtureCosigned, 0) }
	w.Round(logclient.Dir(dir), nil)

	before := replay.Replay(replay.FromTrust(doc), entries)
	genuine := &entry.Envelope{V: 1, T: "revoke", Net: doc.Net, TS: 1790000000,
		Prev: before.Previous("revoke", "printer"), Body: map[string]any{"device_id": "printer"}}
	for _, name := range []string{"signer1", "signer2", "signer3"} {
		key := fixtureSeedKey(t, name)
		if _, ok := before.Signers[entry.Kid(key.Public().(ed25519.PublicKey))]; ok {
			if err := entry.Sign(genuine, key, "signer"); err != nil {
				t.Fatal(err)
			}
		}
	}
	stripped := *genuine
	stripped.Sigs = nil
	for _, env := range []*entry.Envelope{&stripped, genuine} {
		raw, err := entry.Encode(env)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}

	var repeated []Alert
	for _, a := range w.Round(logclient.Dir(dir), nil) {
		if a.Rule == "repeated-entry" {
			repeated = append(repeated, a)
		}
	}
	if len(repeated) != 1 || !strings.Contains(repeated[0].Message, "judged on its own") {
		t.Fatalf("want one repeated-entry alert reporting an attempt: %+v", repeated)
	}
}
