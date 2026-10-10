package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
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

// D-074 (d): "the same keys" is the same verifier key -- name, algorithm and
// public key -- compared as canonical text. Here the policy carries pi's own
// public key under another key name, everything else honest, so a reader that
// compared parsed public keys accepts the file. §10 matches a cosignature line
// by name and key id, so a node that took the policy's key would match none of
// pi's real cosignatures.
func TestAPolicyKeyUnderAnotherNameIsADifferentKey(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "trust-bad", "48-policy-witness-key-renamed.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "another in the policy") {
		t.Fatalf("a policy key under another name passed correspondence: %v", err)
	}
	honest, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	control, err := Parse(honest)
	if err != nil {
		t.Fatal(err)
	}
	listed := control.Witnesses[0].Key
	if doc.Witnesses[0].Key != listed {
		t.Fatal("the witness entry changed too; only the policy's key may differ")
	}
	var renamed string
	for _, line := range strings.Split(doc.Policy, "\n") {
		if fields := strings.Fields(line); len(fields) >= 3 && fields[0] == "witness" &&
			fields[1] == control.Witnesses[0].Name {
			renamed = fields[2]
		}
	}
	a, err := note.ParseVerifierKey(listed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := note.ParseVerifierKey(renamed)
	if err != nil {
		t.Fatalf("the policy's key is not a valid verifier key, so syntax refuses it: %v", err)
	}
	if string(a.Public) != string(b.Public) || a.Name == b.Name {
		t.Fatalf("the policy's key must be the listed public key under another name; "+
			"got %q against %q", renamed, listed)
	}
	doc.Policy = strings.ReplaceAll(doc.Policy, renamed, listed)
	if err := doc.Validate(); err != nil {
		t.Fatalf("restoring the key's name did not repair the trust file: %v", err)
	}
}
