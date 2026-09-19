package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The reference implementation produced `trust.toml`; this rendering must be
// the same bytes. §9.2 has one shape, not one per implementation.
func TestToTOMLMatchesTheVector(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(root, "trust.toml"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := anchor.ToTOML()
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("rendering differs.\n got:\n%s\nwant:\n%s", got, want)
	}
}

// The fingerprint in the comment is the whole point of the rendering: it is
// what an operator compares out of band.
func TestTheRenderingCarriesTheFingerprint(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := anchor.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	got, err := anchor.ToTOML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, fingerprint) {
		t.Errorf("the rendering does not carry the fingerprint %s", fingerprint)
	}
}
