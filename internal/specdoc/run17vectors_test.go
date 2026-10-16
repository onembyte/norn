package specdoc

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRunSeventeenGoCasesAreIndexedAndCiteRawRules(t *testing.T) {
	doc := load(t)
	coverage, _ := doc.Section("12.1")
	index, _ := doc.Section("12")
	paths := map[string][]string{
		"fork":              {"bad-split-zero-with-a-root.cbor", "bad-declared-length-past-the-file.cbor", "bad-empty-map-key.cbor"},
		"proofs-bad":        {"short-proof-hash.bundle", "request-device-pk-small-order.bundle", "pk-length-under-own-id.bundle"},
		"replayed-policy":   {"evidence.cbor", "nas.bundle"},
		"quorum-none":       {"uncosigned.checkpoint", "../served/checkpoint"},
		"genesis-unapplied": {"checkpoint", "sound/checkpoint"},
	}
	expected := map[string]map[string]string{
		"replayed-policy":   {"evidence-fresh": "accept", "evidence-informed": "held", "bundle-fresh": "accept", "bundle-informed": "quorum"},
		"quorum-none":       {"uncosigned": "accept", "cosigned-no-clock": "accept"},
		"genesis-unapplied": {"unapplied": "genesis", "sound": "accept"},
	}
	for dir, files := range paths {
		if dir != "fork" && dir != "proofs-bad" && !strings.Contains(index.Body, "`"+dir+"/`") {
			t.Errorf("§12 must index %s/", dir)
		}
		for _, file := range files {
			if !strings.Contains(coverage.Body, dir+"/"+file) {
				t.Errorf("§12.1 must cite %s/%s", dir, file)
			}
		}
		var manifest struct {
			Cases []struct{ Name, File, Reader, Serve, Trust string }
			Codes map[string]string
			Rules map[string]struct{ Section, Says string }
		}
		readJSON(t, filepath.Join(vectorRoot(t), dir, "cases.json"), &manifest)
		if codes, ok := expected[dir]; ok && !reflect.DeepEqual(codes, manifest.Codes) {
			t.Errorf("%s must name every fixed reader answer: %v", dir, manifest.Codes)
		}
		if codes, ok := expected[dir]; ok && len(manifest.Cases) != len(codes) {
			t.Errorf("%s must list every reader case once", dir)
		}
		seen := map[string]bool{}
		for _, c := range manifest.Cases {
			if dir == "fork" || dir == "proofs-bad" {
				matched := false
				for _, file := range files {
					matched = matched || strings.TrimSuffix(strings.TrimSuffix(file, ".cbor"), ".bundle") == c.Name
				}
				if !matched {
					continue
				}
			}
			if seen[c.Name] {
				t.Errorf("%s repeats %s", dir, c.Name)
			}
			seen[c.Name] = true
			if dir == "replayed-policy" {
				file, reader := "evidence.cbor", "fresh"
				if strings.HasPrefix(c.Name, "bundle-") {
					file = "nas.bundle"
				}
				if strings.HasSuffix(c.Name, "-informed") {
					reader = "informed"
				}
				if c.File != file || c.Reader != reader {
					t.Errorf("%s names wrong file or reader: %+v", c.Name, c)
				}
			}
			if dir == "genesis-unapplied" {
				serve, anchor := ".", "trust.cbor"
				if c.Name == "sound" {
					serve, anchor = "sound", "../trust.cbor"
				}
				if c.Serve != serve || c.Trust != anchor {
					t.Errorf("%s names wrong served log or anchor: %+v", c.Name, c)
				}
			}
			rule, ok := manifest.Rules[c.Name]
			if !ok || manifest.Codes[c.Name] == "" {
				t.Errorf("%s/%s needs code and rule", dir, c.Name)
				continue
			}
			section, ok := doc.Section(rule.Section)
			if !ok {
				t.Fatalf("missing section %s", rule.Section)
			}
			found := false
			for _, line := range strings.Split(section.Body, "\n") {
				found = found || rule.Says != "" && strings.Contains(line, rule.Says)
			}
			if !found {
				t.Errorf("%s/%s must cite one raw line of §%s: %q", dir, c.Name, rule.Section, rule.Says)
			}
		}
	}
}
