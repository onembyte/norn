package trust

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/note"
)

// Each run-18 anchor changes one field. Restoring it must recover the whole
// honest document, so another broken member cannot stand in for its rule.
func TestTheRunEighteenTrustNegativesRepairOneField(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	honest := value.(map[string]any)
	for _, name := range []string{"56-policy-log-key-renamed", "57-log-url-bytes", "58-anchor-max-lag-text", "59-witness-url-uint"} {
		t.Run(name, func(t *testing.T) {
			doc := trustBad(t, name)
			damaged, err := cbor.Encode(doc)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(damaged)
			if err == nil {
				err = parsed.Validate()
			}
			if err == nil {
				t.Fatal("negative accepted")
			}
			t.Logf("negative refused: %v", err)
			switch name {
			case "56-policy-log-key-renamed":
				policy := doc["policy"].(string)
				var renamed string
				for _, line := range strings.Split(policy, "\n") {
					fields := strings.Fields(line)
					if len(fields) >= 2 && fields[0] == "log" {
						renamed = fields[1]
					}
				}
				a, err := note.ParseVerifierKey(renamed)
				if err != nil {
					t.Fatal(err)
				}
				b, err := note.ParseVerifierKey(doc["log_key"].(string))
				if err != nil {
					t.Fatal(err)
				}
				if string(a.Public) != string(b.Public) || a.Name == b.Name || a.Alg != b.Alg {
					t.Fatal("only the policy log verifier name may differ")
				}
				doc["policy"] = strings.Replace(policy, renamed, doc["log_key"].(string), 1)
			case "57-log-url-bytes":
				urls := doc["log_urls"].([]any)
				url, ok := urls[0].([]byte)
				if !ok {
					t.Fatal("log URL is not bytes")
				}
				urls[0] = string(url)
			case "58-anchor-max-lag-text":
				anchor := doc["anchor"].(map[string]any)
				if anchor["max_lag"] != "86400" {
					t.Fatal("max_lag is not text 86400")
				}
				anchor["max_lag"] = uint64(86400)
			case "59-witness-url-uint":
				witness := doc["witnesses"].([]any)[0].(map[string]any)
				if witness["url"] != uint64(1) {
					t.Fatal("witness URL is not uint 1")
				}
				witness["url"] = honest["witnesses"].([]any)[0].(map[string]any)["url"]
			}
			if !reflect.DeepEqual(doc, honest) {
				t.Fatal("one-field repair differs from the honest anchor")
			}
			repaired, err := cbor.Encode(doc)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err = Parse(repaired)
			if err == nil {
				err = parsed.Validate()
			}
			if err != nil {
				t.Fatalf("one-field repair: %v", err)
			}
			t.Log("one-field repair accepted")
		})
	}
}
