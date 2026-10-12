package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/trust"
)

func TestTheFixtureAnchorComesWholeFromItsTrustFile(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _, _, err := loadFixture(root)
	if err != nil {
		t.Fatal(err)
	}
	if anchor.LogKey != doc.LogKey || anchor.Policy != doc.Policy {
		t.Fatal("fixture anchor lost trust fields")
	}
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(root)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "trust.toml")
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text = []byte(strings.Replace(string(text), "6e6f726e2d746573746e65742d303031", "00000000000000000000000000000000", 1))
	if err := os.WriteFile(path, text, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadFixture(dir); err == nil {
		t.Fatal("manifest and trust file can disagree about the network")
	}
}
