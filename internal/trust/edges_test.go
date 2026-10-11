package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
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

// D-074 (f): a key id is lowercase hex and a key name is one or more ASCII
// bytes 0x21-0x7E without '+'. Each file breaks one of those on pi's key, in
// the witness array and the policy alike, so correspondence cannot refuse it
// first -- and putting pi's honest key back in both places repairs the file.
func TestTheKeyIDAndKeyNameVectorsAreTheirOnlyFault(t *testing.T) {
	honest, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	control, err := Parse(honest)
	if err != nil {
		t.Fatal(err)
	}
	listed := control.Witnesses[0].Key
	for _, c := range []struct {
		name  string
		fault func(name, id string) bool
	}{
		{"49-witness-key-id-uppercase", func(_, id string) bool { return id != strings.ToLower(id) }},
		{"50-witness-key-name-not-ascii", func(name, _ string) bool {
			return strings.IndexFunc(name, func(r rune) bool { return r > 0x7e }) >= 0
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "trust-bad", c.name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			if doc, err := Parse(raw); err == nil {
				if err := doc.Validate(); err == nil {
					t.Fatal("accepted")
				}
			}
			// The damaged key, read from the CBOR itself: the trust parser
			// refuses it before handing anything back.
			value, err := cbor.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			doc := value.(map[string]any)
			witness := doc["witnesses"].([]any)[0].(map[string]any)
			key := witness["key"].(string)
			parts := strings.SplitN(key, "+", 3)
			if len(parts) != 3 || !c.fault(parts[0], parts[1]) {
				t.Fatalf("pi's key %q does not carry this case's fault", key)
			}
			policy := doc["policy"].(string)
			if !strings.Contains(policy, "witness pi "+key+" ") {
				t.Fatal("the policy does not carry the same damaged key, so correspondence decides")
			}
			witness["key"] = listed
			doc["policy"] = strings.ReplaceAll(policy, key, listed)
			repaired, err := cbor.Encode(doc)
			if err != nil {
				t.Fatal(err)
			}
			fixed, err := Parse(repaired)
			if err == nil {
				err = fixed.Validate()
			}
			if err != nil {
				t.Fatalf("putting pi's honest key back did not repair the file: %v", err)
			}
		})
	}
}
