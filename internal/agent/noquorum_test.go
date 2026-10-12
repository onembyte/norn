package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

// startNode is New with what these tests vary: the anchor, the mode, the
// setting, and the state directory a previous run may have left.
func startNode(t *testing.T, doc *trust.Trust, dir string, mode reconcile.Mode,
	allow bool, stateDir string) (*Agent, error) {
	t.Helper()
	return New(Config{
		Anchor: doc, Fetcher: logclient.Dir(dir), Device: peertable.NewFake(), Mode: mode,
		RunDir: t.TempDir(), StateDir: stateDir, AllowNoQuorum: allow,
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
}

// §13.2 (D-072 (e)): an enforcing node does not start on a `quorum none`
// trust file unless configured to, and says what to set; `observe` writes
// nothing and always starts. The fixture's own trust file starts in every
// mode, so the refusal is the policy's.
func TestAnEnforcingNodeDoesNotStartOnNoQuorum(t *testing.T) {
	dir, _, _ := writableLog(t)
	for _, c := range []struct {
		mode   reconcile.Mode
		allow  bool
		starts bool
	}{
		{reconcile.Owner, false, false}, {reconcile.Watchdog, false, false},
		{reconcile.Observe, false, true},
		{reconcile.Owner, true, true}, {reconcile.Watchdog, true, true},
	} {
		_, err := startNode(t, quorumNoneAnchor(t), dir, c.mode, c.allow, t.TempDir())
		switch {
		case c.starts && err != nil:
			t.Errorf("%s with allow_no_quorum=%v did not start: %v", c.mode, c.allow, err)
		case !c.starts && err == nil:
			t.Errorf("%s started on a quorum-none trust file without allow_no_quorum", c.mode)
		case !c.starts && !strings.Contains(err.Error(), "allow_no_quorum"):
			t.Errorf("%s's refusal does not say what to set: %v", c.mode, err)
		}
		if _, err := startNode(t, anchor(t), dir, c.mode, false, t.TempDir()); err != nil {
			t.Errorf("%s did not start on the fixture's own trust file: %v", c.mode, err)
		}
	}
}

// appendPolicy writes a real `policy` entry, signed by every root the fixture
// leaves in place.
func appendPolicy(t *testing.T, store *tlogstore.Store, text string) {
	t.Helper()
	env := &entry.Envelope{Prev: storePrev(t, store, "policy", ""), V: entry.Version, T: "policy", Net: anchor(t).Net, TS: 1_760_600_000,
		Body: map[string]any{"text": text}}
	for _, name := range []string{"root1", "root2", "root3", "root4"} {
		if err := entry.Sign(env, fixtureKey(t, name), "root"); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(raw); err != nil {
		t.Fatal(err)
	}
}

// Effective is the policy the node would verify under (§9.4): a published
// policy it restored replaces the trust file's, in both directions. A
// `quorum none` trust file over a log whose roots published a quorum starts;
// a trust file with a quorum over a log whose roots lowered it to none, once
// that head is restored, does not -- and the refusal says where the policy
// came from.
func TestTheRestoredPolicyIsTheOneThatCounts(t *testing.T) {
	dir, store, _ := writableLog(t)
	raised := t.TempDir()
	observer, err := startNode(t, quorumNoneAnchor(t), dir, reconcile.Observe, false, raised)
	if err != nil {
		t.Fatal(err)
	}
	if err := observer.Once(); err != nil {
		t.Fatal(err)
	}
	if _, err := startNode(t, quorumNoneAnchor(t), dir, reconcile.Owner, false, raised); err != nil {
		t.Errorf("an owner node holding a head whose roots published a quorum did not start: %v", err)
	}

	appendPolicy(t, store, quorumNoneAnchor(t).Policy)
	lowered := t.TempDir()
	observer, err = startNode(t, anchor(t), dir, reconcile.Observe, false, lowered)
	if err != nil {
		t.Fatal(err)
	}
	if err := observer.Once(); err != nil {
		t.Fatal(err)
	}
	_, err = startNode(t, anchor(t), dir, reconcile.Owner, false, lowered)
	if err == nil {
		t.Fatal("an owner node holding a head whose roots lowered the quorum to none started")
	}
	if !strings.Contains(err.Error(), "published") || !strings.Contains(err.Error(), "allow_no_quorum") {
		t.Errorf("the refusal does not say the policy was published, or what to set: %v", err)
	}
	if _, err := startNode(t, anchor(t), dir, reconcile.Owner, true, lowered); err != nil {
		t.Errorf("with allow_no_quorum it did not start: %v", err)
	}
}

// §13.2 (D-072 (e)): a `policy` entry lowering the quorum to `none` while the
// node runs does not stop it -- it keeps enforcing -- and an `owner` or
// `watchdog` node not configured for it says so on the degraded cadence,
// because its next start will refuse. A node that opted in, and an observer,
// hear nothing new: nothing about them changes at a restart.
func TestAPolicyLoweredToNoneWhileRunningIsSaidOnACadence(t *testing.T) {
	for _, c := range []struct {
		name  string
		mode  reconcile.Mode
		allow bool
		said  bool
	}{
		{"owner", reconcile.Owner, false, true},
		{"watchdog", reconcile.Watchdog, false, true},
		{"observe", reconcile.Observe, false, false},
		{"owner with allow_no_quorum", reconcile.Owner, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir, store, _ := writableLog(t)
			var mono time.Duration
			rec := &recorder{}
			fake := peertable.NewFake()
			a, err := New(Config{
				Anchor: anchor(t), Fetcher: logclient.Dir(dir), Device: fake, Mode: c.mode,
				RunDir: t.TempDir(), AllowNoQuorum: c.allow, Emit: rec.emit,
				Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
				Mono: func() time.Duration { return mono },
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Once(); err != nil {
				t.Fatal(err)
			}
			if c.mode != reconcile.Owner {
				peers, _ := a.desired(a.held(), peertable.Key{})
				fake.Inject(peers...)
			}
			if got := rec.kinds()[NoQuorum]; got != 0 {
				t.Fatalf("%s alarms under the fixture's 2-of-3 policy", NoQuorum)
			}
			before := tableKeys(t, fake)
			if len(before) == 0 {
				t.Fatal("the node enforces nothing before the policy changes")
			}
			appendPolicy(t, store, quorumNoneAnchor(t).Policy)
			want := func(n int) int {
				if c.said {
					return n
				}
				return 0
			}
			for _, step := range []struct {
				at   time.Duration
				want int
			}{
				{time.Minute, want(1)}, {2 * time.Minute, want(1)}, {5 * time.Minute, want(1)},
				{time.Minute + DefaultDegradedAlarmEvery, want(2)},
				{2*time.Minute + DefaultDegradedAlarmEvery, want(2)},
				{time.Minute + 2*DefaultDegradedAlarmEvery, want(3)},
			} {
				mono = step.at
				if err := a.Once(); err != nil {
					t.Fatalf("at %s: %v", step.at, err)
				}
				if got := rec.kinds()[NoQuorum]; got != step.want {
					t.Errorf("at %s: %s alarms = %d, want %d", step.at, NoQuorum, got, step.want)
				}
			}
			if got := tableKeys(t, fake); !sameKeys(got, before) {
				t.Errorf("the lowered policy changed the table: %d peers, had %d", len(got), len(before))
			}
			if c.said {
				msg := ""
				for _, e := range rec.events {
					if e.Kind == NoQuorum {
						msg = e.Message
					}
				}
				for _, phrase := range []string{"quorum none", "keeps enforcing", "next start", "allow_no_quorum"} {
					if !strings.Contains(msg, phrase) {
						t.Errorf("the %s alarm does not say %q: %s", NoQuorum, phrase, msg)
					}
				}
			}
		})
	}
}
