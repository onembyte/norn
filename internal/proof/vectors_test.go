package proof

import (
	"encoding/json"
	"github.com/onembyte/norn/internal/trust"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
)

// Cold-model gate run 5, defect G12. §8.1 said the bundle format carries
// "domain `norn/proof/v1`", and the six-key table below that sentence has no
// domain in it, no signature for a domain prefix to separate, and the string
// appears nowhere else in the document. The bundles are byte-canonical
// six-key maps, so the domain is emitted nowhere -- and an implementer cannot
// tell whether they are required to produce it or to check for it.
//
// The table and the artifact are now compared, so the section cannot describe
// a format the suite does not ship.

var reKeyRow = regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|")

func TestTheBundleTableDescribesTheShippedBundles(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(spec)
	start := strings.Index(text, "### 8.1")
	if start < 0 {
		t.Fatal("§8.1 is missing")
	}
	end := strings.Index(text[start:], "\n\nChecking a bundle")
	if end < 0 {
		t.Fatal("§8.1 no longer has its key table")
	}
	var described []string
	for _, m := range reKeyRow.FindAllStringSubmatch(text[start:start+end], -1) {
		described = append(described, m[1])
	}
	sort.Strings(described)
	if len(described) == 0 {
		t.Fatal("§8.1 describes no keys")
	}

	bundles, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors",
		"proofs", "*.bundle"))
	if err != nil || len(bundles) == 0 {
		t.Fatalf("no proof bundles ship: %v", err)
	}
	raw, err := os.ReadFile(bundles[0])
	if err != nil {
		t.Fatal(err)
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := value.(map[string]any)
	if !ok {
		t.Fatal("a bundle is not a CBOR map")
	}
	var actual []string
	for key := range m {
		actual = append(actual, key)
	}
	sort.Strings(actual)

	if strings.Join(described, ",") != strings.Join(actual, ",") {
		t.Errorf("§8.1 and the shipped bundles disagree about the format:\n"+
			"  §8.1 describes %v\n  %s carries   %v",
			described, filepath.Base(bundles[0]), actual)
	}
}

// And the claim that started it: a domain string nothing emits.
func TestTheBundleClaimsNoDomainItDoesNotCarry(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(spec), "norn/proof/v1") {
		t.Error("§8.1 names a domain `norn/proof/v1` that appears in no field, covers " +
			"no signature, and is emitted by nothing: an implementer cannot tell " +
			"whether they must produce it")
	}
}

// §12.1 named four proof-bundle refusals -- wrong entry, foreign checkpoint,
// tampered proof, wrong log key -- and shipped none of them. Run 5 built two
// itself to check its work, which is the reader doing the suite's job.

func TestEveryProofNegativeIsRefused(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "proofs-bad")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatalf("the proof negatives are missing: %v", err)
	}
	var doc struct {
		LogKey string                        `json:"log_key"`
		Cases  []struct{ Name, Says string } `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 4 {
		t.Fatalf("%d proof negatives; §12.1 names four", len(doc.Cases))
	}

	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(dir, c.Name+".bundle"))
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := Decode(body)
			if err != nil {
				if !strings.Contains(err.Error(), c.Says) {
					t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.Says)
				}
				return
			}
			err = bundle.Check(shippedAnchor(t))
			if err == nil {
				t.Fatal("accepted a bundle that proves nothing about this log")
			}
			if !strings.Contains(err.Error(), c.Says) {
				t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.Says)
			}
		})
	}
}

// Cold-model gate run 7, defect J3. §8 sells a bundle as self-contained --
// "checked by someone holding only `norn.trust`" -- and §8.1's procedure said
// only "verify the checkpoint note under `norn.trust.log_key`". §11.1, for the
// same kind of embedded checkpoint, says "verify both checkpoints per §10 --
// this network's origin, this network's log key, and a satisfied witness
// quorum." Two variants passed the whole suite: one that never checked the
// quorum, and one that never checked the origin.
//
// A bundle whose checkpoint carries no witness corroboration proves only that
// the log said so, which is the one thing a transparency log is not allowed to
// be believed about on its own.
// shippedAnchor is the fixture's trust file, as a bundle reader holds it.
func shippedAnchor(t *testing.T) Anchor {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Anchor{Origin: doc.Origin, LogKey: doc.LogKey, Policy: doc.Policy}
}

func TestABundleNeedsTheSameCheckpointChecksAsEvidence(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "proofs-bad")
	for _, name := range []string{"no-quorum", "wrong-origin"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, name+".bundle"))
			if err != nil {
				t.Fatalf("the vector for this check is missing: %v", err)
			}
			bundle, err := Decode(raw)
			if err != nil {
				return // refused at the encoding layer, which is also a refusal
			}
			if err := bundle.Check(shippedAnchor(t)); err == nil {
				t.Error("accepted a bundle whose checkpoint is not this network's, or " +
					"carries no quorum; §8 promises it can be checked by somebody " +
					"holding only the trust file")
			}
		})
	}
}

// Cold-model gate run 7, defect J8. §4.0 states `MAX_ENTRY_BYTES` and §8.1,
// §11.1 and §9 each say "deterministic CBOR per §4.0" -- so a reader applies
// the entry cap to every artifact, and a *valid* bundle wrapping a maximal
// entry necessarily exceeds it. Our own decoder did exactly that.
func TestABundleMayWrapAMaximalEntry(t *testing.T) {
	// An entry at the largest size §6 can serve, wrapped in a bundle. The
	// bundle is necessarily larger, and refusing it would make the largest
	// legal entry unprovable.
	entry := make([]byte, cbor.MaxEntryBytes)
	bundle := &Bundle{Device: "d", Index: 0, Entry: entry, Checkpoint: "x\n1\nAA==\n\n"}
	raw, err := bundle.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= cbor.MaxEntryBytes {
		t.Fatalf("this bundle is %d bytes, which does not exceed the entry cap; the "+
			"test proves nothing", len(raw))
	}
	if _, err := Decode(raw); err != nil {
		t.Errorf("a bundle wrapping the largest servable entry was refused: %v\n"+
			"The entry cap is §6's uint16 framing and cannot apply to a document "+
			"that wraps an entry.", err)
	}
}

// --- Cold-model gate run 8, defect D25 ----------------------------------
//
// §8.1 calls the bundle "a closed map of exactly these six keys" and says
// `device` is "the `device_id` this bundle proves". The schema was closed and
// the version checked, and neither had a vector; the binding between `device`
// and the entry was not checked at all.
//
// That last one matters. A bundle's authority is the inclusion proof, which
// shows the *entry* is in the log — it says nothing about the label beside it.
// A bundle reading `device: "nas"` around `printer`'s entry proves exactly as
// much as an honest one, and a consumer keying on `device` believes something
// no proof established.

func TestEveryBundleSchemaRuleHasItsCase(t *testing.T) {
	for _, want := range []string{"open-schema", "wrong-version", "device-not-in-entry"} {
		t.Run(want, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "proofs-bad", want+".bundle"))
			if err != nil {
				t.Fatalf("§8.1 states this rule and no vector reaches it: %v", err)
			}
			if _, err := Decode(raw); err == nil {
				// A schema rule may be enforced at Decode or at Check; both
				// are refusals, and which one owns it is this format's choice.
				t.Logf("%s decodes; Check must refuse it", want)
			}
		})
	}
}
