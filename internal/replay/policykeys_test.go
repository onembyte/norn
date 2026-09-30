package replay

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
)

// Cold-model gate run 12, defect D10. §9.1 compares keys as text and never
// parses one, so a `policy` entry naming a note key where a cosignature key
// belongs replayed into the state and left a quorum nobody could meet. §5.1
// now refuses it; this pins that only the key rule does.
func TestAPolicyNamingANoteKeyAsAWitnessIsDecode(t *testing.T) {
	anchor, entries, m := loadCase(t, filepath.Join(vectorRoot(), "log"))
	r := &replayer{verify: realVerify}
	index, name, _ := exactName(t, m, "bad-policy-witness-key-not-a-cosigner")
	neg := envNamed(t, m, name)
	_, posName, _ := exactName(t, m, "policy")
	pos := envNamed(t, m, posName)

	// Shape: the grammar accepts it, the root quorum is met, and it differs
	// from an accepted policy in exactly one witness line's key.
	text, _ := neg.Body["text"].(string)
	rules, err := policy.Parse(text)
	if err != nil {
		t.Fatalf("the grammar refuses it, so the parse rule refuses it first: %v", err)
	}
	before := Replay(anchor, entries[:index])
	if r.countRole(before, neg, "root") < before.RootThr {
		t.Fatal("short of a root quorum, so `threshold` could refuse it")
	}
	var notCosigners int
	for _, w := range rules.Witnesses {
		v, err := note.ParseVerifierKey(w.Key)
		if err != nil {
			t.Fatalf("witness %s: the key does not parse at all; the case is a note key, not nonsense", w.Name)
		}
		if !v.IsCosigner() {
			notCosigners++
		}
	}
	if notCosigners != 1 {
		t.Fatalf("%d witness keys are not cosignature keys; the case changes exactly one", notCosigners)
	}
	posText, _ := pos.Body["text"].(string)
	posLines, negLines := strings.Split(posText, "\n"), strings.Split(text, "\n")
	if len(posLines) != len(negLines) {
		t.Fatalf("%d and %d lines; the case is the first policy entry with one key swapped", len(posLines), len(negLines))
	}
	var differ int
	for i := range posLines {
		if posLines[i] != negLines[i] {
			differ++
		}
	}
	if differ != 1 {
		t.Errorf("%d lines differ from the first policy entry; the case changes one witness line", differ)
	}

	// Verdict, from the replay.
	refused := map[uint64]string{}
	for _, rj := range Replay(anchor, entries).Rejected {
		refused[rj.Index] = rj.Reason
	}
	if refused[uint64(index)] != ReasonDecode {
		t.Errorf("%s: refused %q, want decode", name, refused[uint64(index)])
	}
}
