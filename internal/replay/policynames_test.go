package replay

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
)

// D-078 (2), cold gate run 15's G10: the policy in force with `pi` renamed
// `zürich`, root-signed, with the correct `prev`, is `decode` -- its text does
// not parse. Renamed `zurich` it is accepted, so the name is the only fault.
func TestAPolicyEntryWithANameOutsideTheGrammarIsDecode(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	before := Replay(anchor, entries)
	for name, want := range map[string]string{"zürich": ReasonDecode, "zurich": ""} {
		text := strings.NewReplacer("witness pi ", "witness "+name+" ", " pi ", " "+name+" ").Replace(before.Policy)
		if !strings.Contains(text, "witness "+name+" ") {
			t.Fatal("the fixture's policy no longer names pi")
		}
		env := &entry.Envelope{V: 1, T: "policy", Net: anchor.Net, TS: 1790000000,
			Body: map[string]any{"text": text}}
		signAs(t, env, before, "root", "root1", "root2", "root3", "root4")
		after := Replay(anchor, appended(t, entries, env))
		if got := lastOutcome(after, len(entries)); got != want {
			t.Errorf("a policy entry naming %q is %q, want %q", name, got, want)
		}
	}
}
