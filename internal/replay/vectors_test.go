package replay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/entry"
)

// --- Cold-model gate run 10, defect D14 ---------------------------------
//
// §5.1 calls its numbered order normative and rests that claim on vectors
// that are wrong in more than one way at once, so the first matching step
// decides the reason code. Run 10 reported the relative order of step 3 (the
// envelope schema), step 6 (`after`) and step 7 (signature counting) as
// unpinned in all three pairings.
//
// Checked before acting: `100-bad-precedence-after-before-threshold` already
// pins **6 before 7** — swapping those two steps and nothing else turns that
// one entry, and only that entry, from `after` into `threshold`. The pairing
// that really had no vector is **3 before 6**: a reader that decodes
// leniently, reads `after`, and applies the envelope schema afterwards
// reproduced the whole manifest, because no entry was malformed in the
// envelope *and* out of order at the same time.

func logManifest(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "log",
		"manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries []struct{ Name, Reason string } `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range doc.Entries {
		out[e.Name] = e.Reason
	}
	return out
}

func TestTheEnvelopeStepIsPinnedAgainstTheAfterStep(t *testing.T) {
	manifest := logManifest(t)
	var name string
	var index int
	for n := range manifest {
		if strings.HasSuffix(n, "-bad-precedence-decode-before-after") {
			name = n
		}
	}
	if name == "" {
		t.Fatal("no entry is malformed in its envelope AND out of order at once, so " +
			"a reader that reads `after` before applying the envelope schema " +
			"reproduces the whole manifest")
	}
	if got := manifest[name]; got != ReasonDecode {
		t.Errorf("%s is %q; step 3 precedes step 6, so it must be %q", name, got, ReasonDecode)
	}
	if _, err := fmtSscan(name, &index); err != nil {
		t.Fatalf("the entry name does not begin with its index: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "log",
		name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	// Both faults have to be there, or the case pins one step against nothing.
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatalf("the entry must decode (step 2) and fail the envelope check "+
			"(step 3), not fail to decode: %v", err)
	}
	env, ok := value.(map[string]any)
	if !ok {
		t.Fatal("the entry is not a map")
	}
	after, ok := env["after"].(uint64)
	if !ok {
		t.Fatal("the entry carries no `after`, so step 6 has nothing to fire on")
	}
	if after <= uint64(index) {
		t.Errorf("`after` is %d at index %d; step 6 fires only when it is greater",
			after, index)
	}
	var unknown []string
	permitted := map[string]bool{"v": true, "t": true, "net": true, "ts": true,
		"after": true, "body": true, "sigs": true}
	for key := range env {
		if !permitted[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		t.Error("the envelope carries only permitted keys, so step 3 has nothing " +
			"to fire on and the case pins no ordering")
	}
}

// fmtSscan reads the leading index of a log entry's name.
func fmtSscan(name string, into *int) (int, error) {
	n := 0
	for i := 0; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			if i == 0 {
				return 0, errNoIndex
			}
			break
		}
		n = n*10 + int(name[i]-'0')
	}
	*into = n
	return n, nil
}

var errNoIndex = &indexError{}

type indexError struct{}

func (*indexError) Error() string { return "no leading index" }

// --- Cold-model gate run 10, defect D15 ---------------------------------
//
// §5.1's entry-0 step 7 counts genesis signatures against the `roots` and
// `root_thr` **in its own body** — the one place signature checking has no
// earlier state to consult. Which key *set* it resolves against was pinned by
// nothing: `V216_GenesisCountSigners`, which bootstrap-resolves a `role:
// "root"` signature against the body's `signers` as well as its `roots`,
// passed all 236 checks. `18-bootstrap-sigs-wrong-role` varies the role
// **string**, not the key set, and every genesis in the suite was signed by
// keys that are in `roots`.
//
// Genesis requires the two sets disjoint (step 6), so this is a real fork in
// the reading: a genesis signed only by `signers` declaring `role: "root"` is
// a working network under one and `bad-genesis` under the other.

func TestGenesisSignaturesResolveAgainstTheRootsOnly(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors", "genesis")
	raw, err := os.ReadFile(filepath.Join(root, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []string `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var name string
	for _, c := range doc.Cases {
		if strings.HasSuffix(c, "-bootstrap-sigs-from-signers") {
			name = c
		}
	}
	if name == "" {
		t.Fatal("no genesis is signed only by keys in its own `signers`, so a reader " +
			"that bootstrap-resolves a `root` signature against `signers` too " +
			"reproduces the whole suite")
	}

	entries, err := filepath.Glob(filepath.Join(root, name, "*.cbor"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("a genesis case is a one-entry log; found %d (%v)", len(entries), err)
	}
	body, err := os.ReadFile(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	value, err := cbor.Decode(body)
	if err != nil {
		t.Fatalf("the entry must decode: only step 7 may refuse it: %v", err)
	}
	env, _ := value.(map[string]any)
	bodyMap, _ := env["body"].(map[string]any)
	roots := kidSet(t, bodyMap, "roots")
	signers := kidSet(t, bodyMap, "signers")

	sigs, _ := env["sigs"].([]any)
	if len(sigs) == 0 {
		t.Fatal("the entry carries no signatures, so step 7 refuses it for being " +
			"unsigned rather than for the set its keys are in")
	}
	for _, item := range sigs {
		sig, _ := item.(map[string]any)
		role, _ := sig["role"].(string)
		kid, _ := sig["kid"].(string)
		if role != "root" {
			t.Errorf("a signature declares role %q; the case is about the key set, "+
				"not the role string — that is `18-bootstrap-sigs-wrong-role`", role)
		}
		if roots[kid] {
			t.Errorf("signature %s is in `roots`, so it counts under either reading", kid)
		}
		if !signers[kid] {
			t.Errorf("signature %s is in neither set, so it is refused for being a "+
				"stranger's rather than for being a signer's", kid)
		}
	}
}

// kidSet returns the kids of a genesis body's key array.
func kidSet(t *testing.T, body map[string]any, field string) map[string]bool {
	t.Helper()
	list, ok := body[field].([]any)
	if !ok {
		t.Fatalf("the genesis body has no `%s` array", field)
	}
	out := map[string]bool{}
	for _, item := range list {
		pk, ok := item.([]byte)
		if !ok {
			t.Fatalf("`%s` holds a non-byte-string", field)
		}
		out[entry.Kid(pk)] = true
	}
	return out
}
