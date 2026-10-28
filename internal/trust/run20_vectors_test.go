package trust

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
)

// A positive no-log anchor prevents an unrelated extra requirement from
// masking the four trust negatives that deliberately omit the policy log.
func TestRunTwentyTrustReadingsAndNoLogRepairs(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	decode := func(t *testing.T, raw []byte) map[string]any {
		t.Helper()
		value, err := cbor.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		return value.(map[string]any)
	}
	check := func(t *testing.T, doc map[string]any, accept bool) {
		t.Helper()
		raw, err := cbor.Encode(doc)
		if err != nil {
			t.Fatal(err)
		}
		tr, err := Parse(raw)
		if err == nil {
			err = tr.Validate()
		}
		if (err == nil) != accept {
			t.Fatalf("trust accepted=%v, want %v: %v", err == nil, accept, err)
		}
	}
	standard := decode(t, read(t, "trust.cbor"))
	noLog := func(text string) string {
		lines := []string{}
		for _, line := range strings.SplitAfter(text, "\n") {
			if !strings.HasPrefix(line, "log ") {
				lines = append(lines, line)
			}
		}
		return strings.Join(lines, "")
	}
	for _, name := range []string{"name-non-ascii", "policy-without-log"} {
		t.Run(name, func(t *testing.T) {
			var manifest struct{ Cases []string }
			if err := json.Unmarshal(read(t, "trust-good/cases.json"), &manifest); err != nil {
				t.Fatal(err)
			}
			listed := false
			for _, n := range manifest.Cases {
				listed = listed || n == name
			}
			if !listed {
				t.Fatal("positive absent from cases")
			}
			doc := decode(t, read(t, "trust-good/"+name+".cbor"))
			check(t, doc, true)
			if name == "name-non-ascii" {
				if doc["name"] != "réseau-de-test" {
					t.Fatal("wrong UTF-8 label")
				}
				doc["name"] = standard["name"]
			} else {
				if doc["policy"] != noLog(standard["policy"].(string)) {
					t.Fatal("only log line may differ")
				}
				doc["policy"] = standard["policy"]
			}
			a, _ := cbor.Encode(doc)
			if !bytes.Equal(a, read(t, "trust.cbor")) {
				t.Fatal("repair changes another field")
			}
		})
	}
	for _, name := range []string{"60-witness-short-name-mismatch", "44-log-key-base64-cr", "51-witness-key-is-log-key", "53-log-cosignature-without-policy-log", "55-log-key-small-order"} {
		t.Run(name, func(t *testing.T) {
			doc := decode(t, read(t, "trust-bad/"+name+".cbor"))
			check(t, doc, false)
			if strings.HasPrefix(name, "60-") {
				w := doc["witnesses"].([]any)[0].(map[string]any)
				if w["name"] != "pj" {
					t.Fatal("expected array short-name mismatch")
				}
				w["name"] = "pi"
				a, _ := cbor.Encode(doc)
				if !bytes.Equal(a, read(t, "trust.cbor")) {
					t.Fatal("short name is not the sole fault")
				}
			} else {
				text := doc["policy"].(string)
				if noLog(text) != text {
					t.Fatal("policy log must remain absent")
				}
				switch name[:2] {
				case "44":
					key := doc["log_key"].(string)
					if strings.Count(key, "\r") != 1 {
						t.Fatal("expected one CR")
					}
					doc["log_key"] = strings.ReplaceAll(key, "\r", "")
				case "51":
					w := doc["witnesses"].([]any)[0].(map[string]any)
					old := w["key"].(string)
					w["key"] = standard["witnesses"].([]any)[0].(map[string]any)["key"]
					doc["policy"] = strings.ReplaceAll(text, old, w["key"].(string))
				default:
					doc["log_key"] = standard["log_key"]
				}
			}
			check(t, doc, true)
			t.Log("named fault alone repaired; no-log anchor accepts")
		})
	}
}
