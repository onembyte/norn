package logclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every addition, replacement or deletion is applied to a fresh copy, alongside the
// older honest head. A corrupt suffix belongs to no claim that head makes.
func TestD079ShippedGrownLogUsesFullTilesForTheOlderHead(t *testing.T) {
	for _, name := range []string{"older-head-over-full-tiles", "full-tile-gone", "full-bundle-gone", "corrupt-within-prefix", "corrupt-beyond-prefix", "malformed-partial-with-good-full"} {
		t.Run(name, func(t *testing.T) { checkD079GrownLogCase(t, name) })
	}
}

func checkD079GrownLogCase(t *testing.T, name string) {
	t.Helper()
	dir := filepath.Join(vectorRoot(), "grown-log")
	var manifest struct {
		ServeOver string `json:"serve_over"`
		Cases     []servedNegative
		Codes     map[string]string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &manifest); err != nil {
		t.Fatal(err)
	}
	wants := map[string]string{"older-head-over-full-tiles": "accept", "full-tile-gone": "unserved", "full-bundle-gone": "unserved", "corrupt-within-prefix": "tiles", "corrupt-beyond-prefix": "accept", "malformed-partial-with-good-full": "tiles"}
	if manifest.ServeOver != "grown-log" || len(manifest.Cases) != len(wants)+3 {
		t.Fatal("grown-log must serve itself and list all nine cases")
	}
	head := readFile(t, filepath.Join(dir, "checkpoint"))
	if head != readFile(t, filepath.Join(vectorRoot(), "served", "checkpoint")) {
		t.Fatal("the older head must be the fixture's signed and cosigned head")
	}
	for _, path := range []string{"tile/0/000.p/162", "tile/entries/000.p/162"} {
		if _, err := os.Stat(filepath.Join(dir, path)); !os.IsNotExist(err) {
			t.Fatalf("partial path %s must be absent: %v", path, err)
		}
	}
	for _, path := range []string{"tile/0/000", "tile/entries/000"} {
		readFile(t, filepath.Join(dir, path))
	}
	anchor := shippedLogAnchor(t)
	seen := map[string]bool{}
	for _, c := range manifest.Cases {
		if seen[c.Name] {
			t.Fatal("duplicate case " + c.Name)
		}
		seen[c.Name] = true
		if c.Name == name {
			want, ok := wants[c.Name]
			if !ok || manifest.Codes[c.Name] != want {
				t.Fatalf("unexpected or repeated case/code: %s %s", c.Name, manifest.Codes[c.Name])
			}
			sound := runFourteenAnswer(t, dir, anchor, "accept")
			if sound.Checkpoint.Size != 162 || len(sound.Served) != 162 {
				t.Fatal("only the older 162 entries may be consumed")
			}
			copy := servedWith(t, dir, head)
			if c.Remove {
				path := map[string]string{"full-tile-gone": "tile/0/000", "full-bundle-gone": "tile/entries/000"}[c.Name]
				if c.Path != path || path == "" || c.File != "" {
					t.Fatal("the deletion must name its full path alone")
				}
				remove(t, filepath.Join(copy, c.Path))
			} else if c.Name == "malformed-partial-with-good-full" {
				if c.Path != "tile/0/000.p/162" || c.File != "malformed-partial-tile.bin" {
					t.Fatal("case must add the width-162 partial tile")
				}
				changed := readFile(t, filepath.Join(dir, c.File))
				if changed != strings.Repeat("Z", 162*32) {
					t.Fatal("partial must retain p15's exact corrupt bytes")
				}
				full := readFile(t, filepath.Join(copy, "tile/0/000"))
				if err := os.MkdirAll(filepath.Dir(filepath.Join(copy, c.Path)), 0o755); err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(copy, c.Path), changed)
				runFourteenAnswer(t, copy, anchor, "tiles")
				if readFile(t, filepath.Join(copy, "tile/0/000")) != full {
					t.Fatal("the good full tile changed")
				}
				// Repair the added path alone, retaining the good full tile.
				write(t, filepath.Join(copy, c.Path), full[:162*32])
				repaired := runFourteenAnswer(t, copy, anchor, "accept")
				if repaired.Checkpoint.Size != 162 || len(repaired.Served) != 162 {
					t.Fatal("repair must consume only the older head")
				}
				t.Log("malformed added partial: tiles; sound partial-only repair: accept; full tile retained")
				continue
			} else if c.File != "" {
				original := readFile(t, filepath.Join(dir, c.Path))
				changed := readFile(t, filepath.Join(dir, c.File))
				at := 10 * 32
				if c.Name == "corrupt-beyond-prefix" {
					at = 200 * 32
				}
				if c.Path != "tile/0/000" || len(original) != 256*32 || len(changed) != len(original) {
					t.Fatal("mutation must keep a full width-256 hash tile")
				}
				for i := range original {
					want := original[i]
					if i == at {
						want ^= 1
					}
					if changed[i] != want {
						t.Fatalf("only byte %d may change", at)
					}
				}
				write(t, filepath.Join(copy, c.Path), changed)
			} else if c.Name != "older-head-over-full-tiles" {
				t.Fatal("missing case mutation")
			}
			runFourteenAnswer(t, copy, anchor, want)
			t.Logf("grown-log/%s: %s", c.Name, want)
		}
	}
	for name := range wants {
		if !seen[name] {
			t.Error("missing case " + name)
		}
	}
}
