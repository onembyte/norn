package replay

import (
	"crypto/ed25519"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/entry"
)

// D-078 (3), cold gate run 15's M3. A `log_key` whose `pk` is already an
// active log key -- the anchor's, or one a `log_key` entry taught (learned
// keys are never retired, §9.4) -- is `dup-key`, as `signer_add` of a known
// key is. Both implementations appended a second row, with its own
// `since_index` and `overlap`, for a key they already trusted. A new key
// still appends.
func TestALogKeyEntryRepublishingAnActiveKeyIsDupKey(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	before := Replay(anchor, entries)
	seed := sha256.Sum256([]byte("norn/log-key-republish-test"))
	fresh := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	for _, c := range []struct {
		name string
		pk   []byte
		want string
	}{
		{"the anchor's key", publicOf(t, "logkey"), ReasonDupKey},
		{"a learned key", publicOf(t, "logkey2"), ReasonDupKey},
		{"the newest learned key", publicOf(t, "logkey3"), ReasonDupKey},
		{"a new key", fresh, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := &entry.Envelope{V: 1, T: "log_key", Net: anchor.Net, TS: 1790000000,
				Body: map[string]any{"pk": c.pk, "overlap": uint64(60)}}
			signAs(t, env, before, "root", "root1", "root2", "root3", "root4")
			after := Replay(anchor, appended(t, entries, env))
			if got := lastOutcome(after, len(entries)); got != c.want {
				t.Fatalf("a log_key of %s is %q, want %q", c.name, got, c.want)
			}
			if c.want != "" && len(after.LogKeys) != len(before.LogKeys) {
				t.Fatal("a refused log_key changed the log keys")
			}
		})
	}
}
