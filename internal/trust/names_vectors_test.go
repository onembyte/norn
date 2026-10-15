package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
)

func TestShippedTrustWitnessNameRepairsWithThePolicy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust-bad", "54-witness-name-not-ascii.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(raw)
	if err == nil {
		err = doc.Validate()
	}
	if err == nil {
		t.Fatal("Go accepted zürich")
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	fields := value.(map[string]any)
	witnesses := fields["witnesses"].([]any)
	witness := witnesses[0].(map[string]any)
	if witness["name"] != "zürich" || !strings.Contains(fields["policy"].(string), "witness zürich ") {
		t.Fatal("witness and policy do not name zürich")
	}
	witness["name"] = "zurich"
	fields["policy"] = strings.ReplaceAll(fields["policy"].(string), "zürich", "zurich")
	repaired, err := cbor.Encode(fields)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = Parse(repaired)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}
