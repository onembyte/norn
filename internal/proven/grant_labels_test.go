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
	if doc.Comment == "" || len(doc.Cases) < 36 {
		t.Fatal("grant label boundaries are missing")
	}
	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, _ := strings.Cut(string(spec), "### 4.0")
	section, _, _ = strings.Cut(section, "### 4.1")
	for _, c := range doc.Cases {
		t.Run(c.Label, func(t *testing.T) {
			got := Grant(map[string]string{"ip": c.Label})
			if strings.Join(got, ",") != strings.Join(c.Grant, ",") {
				t.Errorf("grant = %v, want %v: %s", got, c.Grant, c.Says)
			}
			if c.Says == "" || strings.Contains(c.Says, "\n") || !strings.Contains(section, c.Says) {
				t.Errorf("§4.0 does not state the case's rule on one line: %q", c.Says)
			}
		})
	}
}
