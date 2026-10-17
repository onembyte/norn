package docclaims

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The repository went public on 2026-10-17, at the owner's request. Three
// things were settled first and must stay settled: a NOTICE that travels with
// every copy (Apache-2.0 §4(d)) and says the licence grants no rights to the
// name (§6); a README that says how Norn was built before a reader finds out
// from the logs; and no published document naming the owner's private
// project, which the history keeps by his decision but the files must not.
func TestThePublicRepositoryCarriesItsNoticeAndHowItWasBuilt(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root(t), "NOTICE"))
	if err != nil {
		t.Fatal("NOTICE is missing")
	}
	notice := strings.Join(strings.Fields(string(raw)), " ")
	for _, want := range []string{
		"Copyright 2026 Franco Michetti",
		"\"Norn\" is a trademark of Franco Michetti",
		"grants no rights to use it",
		"testdata/vectors/ed25519-cctv/",
	} {
		if !strings.Contains(notice, want) {
			t.Errorf("NOTICE does not say %q", want)
		}
	}
	readme := strings.Join(strings.Fields(readme(t)), " ")
	for _, want := range []string{
		"## How it was built",
		"Norn was written with AI assistance",
		"No part of that substitutes for review by people who know this field, or for running it on real networks",
		"See `LICENSE` and `NOTICE`",
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("README.md does not say %q", want)
		}
	}
	private := "gung" + "nir"
	err = filepath.WalkDir(root(t), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata" || d.Name() == ".venv" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(string(body)), private) {
			rel, _ := filepath.Rel(root(t), path)
			t.Errorf("%s names the owner's private project", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
