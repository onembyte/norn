package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// §3.1 item 2, §9: the damaged key is carried into the policy too, so only
// the point rule refuses the file -- and restoring that one key repairs it.
func TestTheNoncanonicalWitnessKeyMakesTheTrustFileInvalid(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "trust-bad", "47-witness-noncanonical-point.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err == nil {
		t.Fatal("noncanonical witness point admitted")
	}
	honest, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	control, err := Parse(honest)
	if err != nil {
		t.Fatal(err)
	}
	bad := doc.Witnesses[0].Key
	if !strings.Contains(doc.Policy, "witness pi "+bad+" ") {
		t.Fatal("the policy does not carry the same damaged key")
	}
	doc.Witnesses[0].Key = control.Witnesses[0].Key
	doc.Policy = strings.ReplaceAll(doc.Policy, bad, control.Witnesses[0].Key)
	if err := doc.Validate(); err != nil {
		t.Fatalf("repairing only the witness key did not repair the trust file: %v", err)
	}
}
