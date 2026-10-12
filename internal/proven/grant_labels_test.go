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
	if doc.Comment == "" || len(doc.Cases) < 3 {
		t.Fatal("grant label boundaries are missing")
	}
	for _, c := range doc.Cases {
		t.Run(c.Label, func(t *testing.T) {
			got := Grant(map[string]string{"ip": c.Label})
			if strings.Join(got, ",") != strings.Join(c.Grant, ",") {
				t.Errorf("grant = %v, want %v: %s", got, c.Grant, c.Says)
			}
		})
	}
}
