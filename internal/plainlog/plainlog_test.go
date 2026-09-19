package plainlog

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/entry"
)

func fixtureEntries(t *testing.T) []*entry.Envelope {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "vectors", "log")
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Entries []struct{ Name string } `json:"entries"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	var out []*entry.Envelope
	for _, e := range manifest.Entries {
		b, err := os.ReadFile(filepath.Join(root, e.Name+".cbor"))
		if err != nil {
			continue // the rejecting vectors include deliberately undecodable bytes
		}
		env, err := entry.Decode(b)
		if err != nil {
			continue
		}
		out = append(out, env)
	}
	return out
}

// Every entry type in the suite must get a real description. The fallback
// exists for a type that does not exist yet; if it ever fires for one that
// does, the log has stopped being readable.
func TestEveryTypeInTheSuiteIsDescribed(t *testing.T) {
	seen := map[string]bool{}
	for _, env := range fixtureEntries(t) {
		got := Describe(env)
		if got == "" {
			t.Errorf("%s described as nothing", env.T)
		}
		if !entry.Types[env.T] {
			// The suite carries an `unknown-type` negative. Replay refuses it;
			// this package still has to print something truthful about it.
			if !strings.Contains(got, "made a "+env.T+" entry") {
				t.Errorf("an unknown type should be described as unknown: %q", got)
			}
			continue
		}
		seen[env.T] = true
		if strings.Contains(got, "made a "+env.T+" entry") {
			t.Errorf("%s fell through to the fallback: %q", env.T, got)
		}
	}
	// The fixture carries one of each; if it stops doing so, this test has
	// quietly narrowed and should say so.
	for _, want := range []string{"genesis", "enroll", "rotate", "revoke", "signer_add",
		"signer_remove", "signer_thr", "root_add", "root_remove", "root_thr",
		"params", "policy", "log_key", "note"} {
		if !seen[want] {
			t.Errorf("the suite no longer carries a %s entry, so this test no longer covers it", want)
		}
	}
}

// The device an enrolment names comes out of the embedded request (§4.3), not
// out of a restatement in the body -- there is no restatement any more.
func TestAnEnrolmentNamesItsDevice(t *testing.T) {
	for _, env := range fixtureEntries(t) {
		if env.T != "enroll" {
			continue
		}
		got := Describe(env)
		if strings.Contains(got, "unreadable") {
			t.Fatalf("could not read the request out of an enrolment: %q", got)
		}
		if !strings.Contains(got, "enrolled ") || !strings.Contains(got, "wireguard ") {
			t.Errorf("an enrolment should name the device and its key: %q", got)
		}
		return
	}
	t.Fatal("no enrolment in the suite")
}

func TestActorsAreNamedByRoleAndKey(t *testing.T) {
	for _, env := range fixtureEntries(t) {
		if env.T != "genesis" {
			continue
		}
		got := Describe(env)
		if !strings.HasPrefix(got, "roots ") {
			t.Errorf("genesis is signed by roots, and the sentence should say so: %q", got)
		}
		for _, sig := range env.Sigs {
			if !strings.Contains(got, sig.Kid[:8]) {
				t.Errorf("the sentence omits signer %s: %q", sig.Kid, got)
			}
		}
		return
	}
	t.Fatal("no genesis in the suite")
}

// A log binds keys, not people. Putting a friendly name on a key would be
// presenting an identity nobody vouched for.
func TestNoInventedNames(t *testing.T) {
	for _, env := range fixtureEntries(t) {
		got := Describe(env)
		for _, invented := range []string{"Alice", "Bob", "admin", "the operator"} {
			if strings.Contains(got, invented) {
				t.Errorf("invented an identity: %q", got)
			}
		}
	}
}

func TestAgo(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := []struct {
		ts   int64
		want string
	}{
		{now.Unix() - 10, "just now"},
		{now.Unix() - 600, "10 min ago"},
		{now.Unix() - 7200, "2 h ago"},
		{now.Unix() - 5*86400, "5 days ago"},
		{now.Unix() + 60, "in the future"},
	}
	for _, c := range cases {
		env := &entry.Envelope{TS: uint64(c.ts)}
		if got := Ago(env, now); got != c.want {
			t.Errorf("ts %d: Ago = %q, want %q", c.ts, got, c.want)
		}
	}
}

func TestAnUnsignedEntrySaysSo(t *testing.T) {
	env := &entry.Envelope{T: "note", Body: map[string]any{"text": "hello"}}
	if got := Describe(env); !strings.HasPrefix(got, "nobody ") {
		t.Errorf("an entry with no signatures should say so: %q", got)
	}
}

func TestParamsListsWhatChanged(t *testing.T) {
	env := &entry.Envelope{T: "params", Body: map[string]any{
		"mmd": uint64(45), "staleness": uint64(600)},
		Sigs: []entry.Signature{{Kid: hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8}), Role: "root"}}}
	got := Describe(env)
	for _, want := range []string{"mmd to 45", "staleness to 600"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q missing from %q", want, got)
		}
	}
}
