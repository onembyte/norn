package proven

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The label table exercises grant derivation without constructing a log.
func checkGrantLabels(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "proven", "grant-labels.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Comment string
		Cases   []struct {
			Label string
			Grant []string
			Says  string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Comment == "" || len(doc.Cases) < 41 {
		t.Fatal("grant label boundaries are missing")
	}
	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, _ := strings.Cut(string(spec), "### 4.0")
	section, _, _ = strings.Cut(section, "### 4.1")
	labels := map[string]bool{}
	for _, c := range doc.Cases {
		labels[c.Label] = true

		t.Run(c.Label, func(t *testing.T) {
			expected := map[string]string{"1:0:0:2:3:0:0:4/128": "1::2:3:0:0:4/128", "10.0.0.1/8, 10.0.0.2/8": "10.0.0.0/8"}
			if want, ok := expected[c.Label]; ok && strings.Join(c.Grant, ",") != want {
				t.Fatalf("manifest grant = %v, want %s", c.Grant, want)
			}
			got := Grant(map[string]string{"ip": c.Label})
			if strings.Join(got, ",") != strings.Join(c.Grant, ",") {
				t.Errorf("grant = %v, want %v: %s", got, c.Grant, c.Says)
			}
			if c.Says == "" || strings.Contains(c.Says, "\n") || !strings.Contains(section, c.Says) {
				t.Errorf("§4.0 does not state the case's rule on one line: %q", c.Says)
			}
		})
	}
	for _, label := range []string{"9.0.0.0/8, 10.0.0.0/8", "2001:db8:0:1:1:1:1:1/128", "2001:db8:0:0:1:1:1:1/128", "1:0:0:2:3:0:0:4/128", "10.0.0.1/8, 10.0.0.2/8"} {
		if !labels[label] {
			t.Errorf("missing grant form %q", label)
		}
	}

}
