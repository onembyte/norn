package specdoc

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The committed vectors are the contract between implementations. Nothing used
// to verify that they still match what the reference implementation produces,
// which is how seven orphan files from a renumbering survived three
// conformance runs. These checks are cheap, need no Python, and run on every
// build.

func vectorRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "vectors")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("vector root: %v", err)
	}
	return root
}

type manifest struct {
	Anchor struct {
		Net         string `json:"net"`
		GenesisHash string `json:"genesis_hash"`
	} `json:"anchor"`
	Entries []struct {
		Index  int    `json:"index"`
		Name   string `json:"name"`
		Reason string `json:"reason"`
	} `json:"entries"`
}

func loadManifest(t *testing.T, path string) manifest {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return m
}

func TestLogHasNoOrphanFiles(t *testing.T) {
	root := vectorRoot(t)
	m := loadManifest(t, filepath.Join(root, "log", "manifest.json"))

	named := map[string]bool{}
	for _, e := range m.Entries {
		named[e.Name] = true
	}
	entries, err := os.ReadDir(filepath.Join(root, "log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range entries {
		name := f.Name()
		if name == "manifest.json" {
			continue
		}
		stem := strings.TrimSuffix(strings.TrimSuffix(name, ".cbor"), ".reason")
		if !named[stem] {
			t.Errorf("log/%s is not named by manifest.json — an orphan sorts between "+
				"live entries and silently corrupts a glob-and-sort reader", name)
		}
	}
}

func TestEveryManifestEntryHasItsFile(t *testing.T) {
	root := vectorRoot(t)
	m := loadManifest(t, filepath.Join(root, "log", "manifest.json"))
	for _, e := range m.Entries {
		path := filepath.Join(root, "log", e.Name+".cbor")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("manifest names %s but %s is missing", e.Name, path)
		}
		if e.Reason == "" {
			continue
		}
		reason := filepath.Join(root, "log", e.Name+".reason")
		got, err := os.ReadFile(reason)
		if err != nil {
			t.Errorf("rejected entry %s has no .reason sidecar", e.Name)
			continue
		}
		if strings.TrimSpace(string(got)) != e.Reason {
			t.Errorf("%s: sidecar says %q, manifest says %q",
				e.Name, strings.TrimSpace(string(got)), e.Reason)
		}
	}
}

func TestEntryNamesAgreeWithTheirIndices(t *testing.T) {
	root := vectorRoot(t)
	m := loadManifest(t, filepath.Join(root, "log", "manifest.json"))
	for _, e := range m.Entries {
		head, _, ok := strings.Cut(e.Name, "-")
		if !ok {
			t.Errorf("entry %d is named %q with no index prefix", e.Index, e.Name)
			continue
		}
		n, err := strconv.Atoi(head)
		if err != nil || n != e.Index {
			t.Errorf("entry %d is named %q; the prefix must be its own index", e.Index, e.Name)
		}
	}
}

func TestGenesisHashInTheManifestIsTheLeafHashOfEntryZero(t *testing.T) {
	root := vectorRoot(t)
	m := loadManifest(t, filepath.Join(root, "log", "manifest.json"))
	raw, err := os.ReadFile(filepath.Join(root, "log", m.Entries[0].Name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte{0x00}, raw...))
	want := m.Anchor.GenesisHash
	if got := hex(sum[:]); got != want {
		t.Errorf("anchor genesis_hash %s but leaf hash of entry 0 is %s", want, got)
	}
}

func hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// TestSpecVectorCitationsResolve guards the failure that broke §12.1 twice:
// the coverage table cited vectors by index, a later insertion shifted every
// index, and the citations silently began naming the wrong entries. Citations
// are by name now, and this fails the build if one stops resolving.
func TestSpecVectorCitationsResolve(t *testing.T) {
	root := vectorRoot(t)
	m := loadManifest(t, filepath.Join(root, "log", "manifest.json"))
	suffixes := map[string]bool{}
	for _, e := range m.Entries {
		if _, rest, ok := strings.Cut(e.Name, "-"); ok {
			suffixes[rest] = true
		}
	}

	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	section := string(spec)
	start := strings.Index(section, "### 12.1")
	end := strings.Index(section, "## 13.")
	if start < 0 || end < 0 {
		t.Fatal("§12.1 not found")
	}

	// §5.2 reason codes share the "bad-" prefix with vector names but are not
	// vectors; listing them keeps the heuristic honest rather than loose.
	reasonCodes := map[string]bool{
		"bad-genesis": true, "bad-thr": true,
	}

	for _, quoted := range backticked(section[start:end]) {
		if !strings.HasPrefix(quoted, "bad-") && !strings.HasSuffix(quoted, "-base") {
			continue
		}
		if reasonCodes[quoted] && !suffixes[quoted] {
			continue
		}
		if !suffixes[quoted] {
			t.Errorf("§12.1 cites vector %q, which no manifest entry matches", quoted)
		}
	}
}

func backticked(text string) []string {
	var out []string
	for {
		i := strings.Index(text, "`")
		if i < 0 {
			return out
		}
		text = text[i+1:]
		j := strings.Index(text, "`")
		if j < 0 {
			return out
		}
		out = append(out, text[:j])
		text = text[j+1:]
	}
}
