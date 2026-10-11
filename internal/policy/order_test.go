package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type orderEvaluation struct {
	Cosigners []string `json:"cosigners"`
	Satisfied bool     `json:"satisfied"`
}

func orderVector(t *testing.T, name string, accept bool, says string) (string, []orderEvaluation) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "policies", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name     string            `json:"name"`
			Accept   bool              `json:"accept"`
			Why      string            `json:"why"`
			Evaluate []orderEvaluation `json:"evaluate"`
		} `json:"cases"`
		Rules map[string]struct{ Section, Says string } `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Cases {
		if c.Name != name {
			continue
		}
		if c.Accept != accept || c.Why == "" {
			t.Fatalf("%s: accept=%v, why=%q", name, c.Accept, c.Why)
		}
		if rule := doc.Rules[name]; rule.Section != "9.1" || rule.Says != says {
			t.Fatalf("%s names the wrong rule: %+v", name, rule)
		}
		return policyText(t, name), c.Evaluate
	}
	t.Fatalf("the %s policy vector is missing", name)
	return "", nil
}

// D-074 (e) permits later directives, but they cannot enlarge the quorum's
// member set. Removing them must preserve every shipped evaluation verdict.
func TestDirectivesAfterQuorumLeaveEveryEvaluationUnchanged(t *testing.T) {
	text, evaluations := orderVector(t, "directive-after-quorum", true, "lines may appear in **any order**")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 6 || lines[2] != "group home any pi" || lines[3] != "quorum home" ||
		!strings.HasPrefix(lines[4], "witness vps ") || lines[5] != "group unused all vps" {
		t.Fatalf("the vector must put an unused witness and group after the quorum: %q", text)
	}
	full, err := Parse(text)
	if err != nil {
		t.Fatalf("directive-after-quorum must parse: %v", err)
	}
	base, err := Parse(strings.Join(lines[:4], "\n") + "\n")
	if err != nil {
		t.Fatalf("removing the trailing directives must leave a valid policy: %v", err)
	}
	want := []orderEvaluation{
		{[]string{}, false}, {[]string{"pi"}, true},
		{[]string{"vps"}, false}, {[]string{"pi", "vps"}, true},
	}
	if !reflect.DeepEqual(evaluations, want) {
		t.Fatalf("the vector must decide all sets of its two witnesses: %+v", evaluations)
	}
	for _, e := range evaluations {
		if got, without := full.Satisfied(e.Cosigners), base.Satisfied(e.Cosigners); got != e.Satisfied || without != e.Satisfied {
			t.Errorf("cosigners %v: full=%v, without trailing lines=%v, want %v", e.Cosigners, got, without, e.Satisfied)
		}
	}
}

// A used group cannot acquire a new meaning through a later definition. The
// final line is the sole fault: without it the policy parses and names pi.
func TestRedefinitionAfterQuorumUseIsTheOnlyFault(t *testing.T) {
	text, _ := orderVector(t, "bad-redefinition-after-use", false, "nothing defined later changes an earlier line")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 6 || lines[3] != "group home any pi" || lines[4] != "quorum home" || lines[5] != "group home any vps" {
		t.Fatalf("the vector must redefine the group the earlier quorum used: %q", text)
	}
	if _, err := Parse(text); err == nil || !strings.Contains(err.Error(), `"home" is already defined`) {
		t.Fatalf("only the duplicate name must refuse bad-redefinition-after-use: %v", err)
	}
	base, err := Parse(strings.Join(lines[:5], "\n") + "\n")
	if err != nil {
		t.Fatalf("removing the redefinition must leave a valid policy: %v", err)
	}
	if !base.Satisfied([]string{"pi"}) || base.Satisfied([]string{"vps"}) {
		t.Error("the original group must be satisfied by pi alone and not by vps alone")
	}
}
