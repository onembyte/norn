package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
)

func TestCaseDistinctPolicyNamesKeepTheirKeysAndQuorum(t *testing.T) {
	const name = "names-differ-in-case"
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "policies", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Cases []struct {
			Name     string
			Accept   bool
			Evaluate []struct {
				Cosigners []string
				Satisfied bool
				Why       string
			}
		}
		Rules map[string]struct{ Section, Says string }
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, c := range m.Cases {
		if c.Name != name {
			continue
		}
		found++
		if !c.Accept || len(c.Evaluate) != 4 || m.Rules[name].Section != "9.1" || m.Rules[name].Says != "Nothing here is case-folded" {
			t.Fatal("missing case-distinct policy rule or evaluations")
		}
		text := policyText(t, name)
		p, err := Parse(text)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Witnesses) != 2 || p.Witnesses[0].Name != "pi" || p.Witnesses[1].Name != "PI" || !strings.HasSuffix(text, "group home 2 pi PI\nquorum home\n") {
			t.Fatal("expected distinct pi and PI definitions")
		}
		a, err := note.ParseVerifierKey(p.Witnesses[0].Key)
		if err != nil {
			t.Fatal(err)
		}
		b, err := note.ParseVerifierKey(p.Witnesses[1].Key)
		if err != nil {
			t.Fatal(err)
		}
		if a.Name != "norn-witness/pi" || b.Name != "norn-witness/vps" || bytes.Equal(a.Public, b.Public) {
			t.Fatal("case distinction must retain two different verifier keys")
		}
		for i, want := range [][]string{{}, {"pi"}, {"PI"}, {"pi", "PI"}} {
			e := c.Evaluate[i]
			if !reflect.DeepEqual(e.Cosigners, want) || e.Satisfied != (i == 3) || e.Why == "" || p.Satisfied(e.Cosigners) != e.Satisfied {
				t.Fatalf("evaluation %d differs: %+v", i, e)
			}
		}
		if _, err := Parse(strings.ReplaceAll(text, "PI", "upper")); err != nil {
			t.Fatal("name-only repair", err)
		}
		t.Log("name-only repair accepted; four evaluation rows matched")
	}
	if found != 1 {
		t.Fatal("missing case-distinct policy")
	}
}
