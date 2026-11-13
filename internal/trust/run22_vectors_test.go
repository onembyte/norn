package trust

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/note"
)

func TestTheRunTwentyTwoTrustCasesRepairOnlyTheirNamedFields(t *testing.T) {
	const root = "../../testdata/vectors/"
	read := func(path string) []byte {
		t.Helper()
		b, err := os.ReadFile(root + path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	decode := func(raw []byte) map[string]any {
		t.Helper()
		v, err := cbor.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		return v.(map[string]any)
	}
	check := func(raw []byte) error {
		d, err := Parse(raw)
		if err == nil {
			err = d.Validate()
		}
		return err
	}
	baseRaw := read("trust.cbor")
	base := decode(baseRaw)
	for _, c := range []struct {
		name, section, says string
		bad                 bool
	}{
		{"log-url-no-scheme", "9.1", "Norn does not parse URL syntax here", false},
		{"long-witness-key-name", "7", "A key name is one or more ASCII bytes", false},
		{"witness-names-differ-in-case", "9.1", "Nothing here is case-folded", false},
		{"62-anchor-type-uint", "9.1", "The two text members are not symmetric", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			folder := "trust-good/"
			if c.bad {
				folder = "trust-bad/"
			}
			var m struct {
				Cases []string
				Says  map[string]string
				Rules map[string]struct{ Section, Says string }
			}
			if err := json.Unmarshal(read(folder+"cases.json"), &m); err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, n := range m.Cases {
				if n == c.name {
					count++
				}
			}
			if count != 1 || m.Rules[c.name].Section != c.section || m.Rules[c.name].Says != c.says || (!c.bad && m.Says[c.name] == "") {
				t.Fatal("missing trust case or rule", c.name)
			}
			raw := read(folder + c.name + ".cbor")
			if err := check(raw); (err != nil) != c.bad {
				t.Fatalf("wrong trust outcome: %v", err)
			}
			doc := decode(raw)
			switch c.name {
			case "log-url-no-scheme":
				if !reflect.DeepEqual(doc["log_urls"], []any{"log.norn.example/testnet"}) {
					t.Fatal("expected one schemeless log URL")
				}
				doc["log_urls"] = base["log_urls"]
			case "long-witness-key-name":
				w := doc["witnesses"].([]any)[0].(map[string]any)
				v := w["key"].(string)
				key, err := note.ParseVerifierKey(v)
				if err != nil {
					t.Fatal(err)
				}
				old := base["witnesses"].([]any)[0].(map[string]any)["key"].(string)
				honest, err := note.ParseVerifierKey(old)
				if err != nil {
					t.Fatal(err)
				}
				if w["name"] != "pi" || key.Name != "norn-witness/"+strings.Repeat("p", 60) || len(key.Name) != 73 || !bytes.Equal(key.Public, honest.Public) || !strings.Contains(doc["policy"].(string), "witness pi "+v+" ") {
					t.Fatal("long verifier name must occur in both halves with short label pi")
				}
				doc["policy"] = strings.ReplaceAll(doc["policy"].(string), v, old)
				w["key"] = old
			case "witness-names-differ-in-case":
				ws := doc["witnesses"].([]any)
				if len(ws) != 3 || ws[0].(map[string]any)["name"] != "pi" || ws[1].(map[string]any)["name"] != "PI" || ws[2].(map[string]any)["name"] != "friend" || !strings.Contains(doc["policy"].(string), "group home 2 pi PI friend\n") {
					t.Fatal("expected distinct pi and PI labels in both halves")
				}
				ws[1].(map[string]any)["name"] = "vps"
				doc["policy"] = strings.ReplaceAll(doc["policy"].(string), " PI", " vps")
			case "62-anchor-type-uint":
				a := doc["anchor"].(map[string]any)
				if a["type"] != uint64(7) {
					t.Fatal("anchor type must be uint seven")
				}
				a["type"] = base["anchor"].(map[string]any)["type"]
			}
			fixed, err := cbor.Encode(doc)
			if err != nil || !bytes.Equal(fixed, baseRaw) {
				t.Fatal("repair changed another field", err)
			}
			if err := check(fixed); err != nil {
				t.Fatal("field-only repair", err)
			}
			t.Log("field-only repair accepted and equals trust.cbor")
		})
	}
}
