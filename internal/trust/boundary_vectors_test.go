package trust

import (
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/note"
)

func checkTrustBoundaries(t *testing.T) {
	for _, name := range []string{"52-name-one-past-the-cap", "53-log-cosignature-without-policy-log"} {
		t.Run(name, func(t *testing.T) {
			doc := trustBad(t, name)
			raw, err := cbor.Encode(doc)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(raw)
			if err == nil {
				err = parsed.Validate()
			}
			if err == nil {
				t.Fatal("negative accepted")
			}
			if strings.Contains(name, "name-one") {
				value := doc["name"].(string)
				if len(value) != 65 {
					t.Fatalf("name has %d bytes", len(value))
				}
				doc["name"] = value[:64]
			} else {
				for _, line := range strings.Split(doc["policy"].(string), "\n") {
					if strings.HasPrefix(line, "log ") {
						t.Fatal("policy log line creates another fault")
					}
				}
				key, err := note.ParseVerifierKey(doc["log_key"].(string))
				if err != nil {
					t.Fatal(err)
				}
				doc["log_key"] = note.VerifierKey(key.Name, key.Public)
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
				t.Fatalf("one-fault repair: %v", err)
			}
		})
	}
}
