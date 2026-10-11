package docclaims

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// contrib/verify-py is a verifier built cold, from SPEC.md and the vectors
// alone, by a model that never saw this implementation (H14). Its value is
// that nobody here wrote it, so it is kept exactly as written: every file's
// digest is recorded in its PROVENANCE.md, and a hand edit fails this guard
// unless the provenance is changed too, in plain sight. If the verifier ever
// disagrees with the suite, that is a finding about SPEC, the vectors or the
// verifier -- recorded, never patched here.
func TestTheIndependentVerifierIsKeptAsWritten(t *testing.T) {
	dir := filepath.Join(root(t), "contrib", "verify-py")
	provenance, err := os.ReadFile(filepath.Join(dir, "PROVENANCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[string]string{}
	row := regexp.MustCompile("(?m)^\\| `([^`]+)` \\| `([0-9a-f]{64})` \\|")
	for _, m := range row.FindAllStringSubmatch(string(provenance), -1) {
		recorded[m[1]] = m[2]
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var present []string
	for _, e := range entries {
		if e.IsDir() || e.Name() == "PROVENANCE.md" {
			continue
		}
		present = append(present, e.Name())
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		want, ok := recorded[e.Name()]
		if !ok {
			t.Errorf("%s is not in PROVENANCE.md's digest table: nothing may be added to the verifier by hand", e.Name())
		} else if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s has digest %s, PROVENANCE.md records %s: the verifier is kept as written", e.Name(), got, want)
		}
	}
	for name := range recorded {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("PROVENANCE.md records %s, which is gone", name)
		}
	}
	if len(present) == 0 {
		t.Fatal("contrib/verify-py holds no files")
	}

	makefile, err := os.ReadFile(filepath.Join(root(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	ci := regexp.MustCompile(`(?m)^ci:(.*)$`).FindStringSubmatch(string(makefile))
	if ci == nil || !strings.Contains(" "+ci[1]+" ", " verify-py ") {
		t.Error("`make ci` does not run `verify-py`: the independent verifier must run wherever the suite is checked")
	}
	if !regexp.MustCompile(`(?m)^verify-py:`).Match(makefile) {
		t.Error("the Makefile has no `verify-py` target")
	}
}

// The cold verifier is sealed: it reads the SPEC it was built from, and a
// normative change after the seal is a check it fails for a reason that is
// not a defect in the suite -- D-076's bound on decimal lines, which the
// second build predates, is the first for this build. Those failures are recorded, one line
// each, in `contrib/verify-py.known-failures`, and `make verify-py` passes
// only when the harness fails exactly those lines: a new failure fails it,
// and so does a recorded one that starts to pass. The list is a debt, not an
// exemption -- its header names the row that pays it with a new cold build,
// and the file goes when that row lands.
func TestTheColdVerifiersKnownFailuresAreRecordedAndOwed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root(t), "contrib", "verify-py.known-failures"))
	if err != nil {
		t.Fatalf("the cold verifier's known failures are not recorded: %v", err)
	}
	var header strings.Builder
	line := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/._-]* expected=.* got=.*$`)
	for _, text := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.HasPrefix(text, "#") {
			header.WriteString(text)
			continue
		}
		if text != "" && !line.MatchString(text) {
			t.Errorf("%q is not a harness line (`<check> expected=… got=…`)", text)
		}
	}
	if !strings.Contains(header.String(), "6.7-r") {
		t.Error("the known failures do not name the row that clears them (6.7-r)")
	}
	makefile, err := os.ReadFile(filepath.Join(root(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	recipe := regexp.MustCompile(`(?ms)^verify-py:.*?\n\n`).Find(makefile)
	if !strings.Contains(string(recipe), "contrib/verify-py.known-failures") {
		t.Error("`make verify-py` does not compare the harness's failures with contrib/verify-py.known-failures")
	}
}
