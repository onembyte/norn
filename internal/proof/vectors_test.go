package proof

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	upstream "golang.org/x/mod/sumdb/tlog"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/trust"
)

func TestRightEdgeInclusionProofAtSize127(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors", "proofs")
	var manifest struct {
		RightEdge struct {
			File  string `json:"file"`
			Size  int64  `json:"size"`
			Index int64  `json:"index"`
		} `json:"right_edge_inclusion"`
	}
	caseBytes, err := os.ReadFile(filepath.Join(root, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(caseBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.RightEdge.File == "" || manifest.RightEdge.Size != 127 ||
		manifest.RightEdge.Index != 126 || manifest.RightEdge.Index != manifest.RightEdge.Size-1 {
		t.Fatalf("cases.json does not name the last leaf at size 127: %+v", manifest.RightEdge)
	}
	var vector struct {
		Size     int64    `json:"size"`
		Index    int64    `json:"index"`
		EntryB64 string   `json:"entry_b64"`
		LeafHash string   `json:"leaf_hash"`
		Root     string   `json:"root"`
		Proof    []string `json:"proof"`
	}
	vectorBytes, err := os.ReadFile(filepath.Join(root, manifest.RightEdge.File))
	if err != nil {
		t.Fatalf("read right-edge proof: %v", err)
	}
	if err := json.Unmarshal(vectorBytes, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Size != manifest.RightEdge.Size || vector.Index != manifest.RightEdge.Index {
		t.Fatalf("proof file describes size/index %d/%d, cases.json says %d/%d",
			vector.Size, vector.Index, manifest.RightEdge.Size, manifest.RightEdge.Index)
	}
	entryBytes, err := base64.StdEncoding.DecodeString(vector.EntryB64)
	if err != nil {
		t.Fatalf("entry_b64: %v", err)
	}
	leaf := tlog.LeafHash(entryBytes)
	if hex.EncodeToString(leaf[:]) != vector.LeafHash {
		t.Fatalf("leaf hash is %s, vector says %s", hex.EncodeToString(leaf[:]), vector.LeafHash)
	}
	rootBytes, err := hex.DecodeString(vector.Root)
	if err != nil || len(rootBytes) != len(upstream.Hash{}) {
		t.Fatalf("root is not a 32-byte hex hash: %q (%v)", vector.Root, err)
	}
	var head upstream.Hash
	copy(head[:], rootBytes)
	proof := make(upstream.RecordProof, len(vector.Proof))
	for i, encoded := range vector.Proof {
		hash, err := hex.DecodeString(encoded)
		if err != nil || len(hash) != len(upstream.Hash{}) {
			t.Fatalf("proof[%d] is not a 32-byte hex hash: %q (%v)", i, encoded, err)
		}
		copy(proof[i][:], hash)
	}
	if err := upstream.CheckRecord(proof, vector.Size, head, vector.Index, leaf); err != nil {
		t.Fatalf("right-edge proof at %d of %d does not verify: %v", vector.Index, vector.Size, err)
	}
}

func TestRightEdgeProofIsNamedInSpecCoverage(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(spec)
	start := strings.Index(text, "### 12.1")
	if start < 0 {
		t.Fatal("SPEC.md has no §12.1 coverage table")
	}
	end := strings.Index(text[start:], "\n## 13.")
	if end < 0 {
		t.Fatal("SPEC.md §12.1 has no end")
	}
	coverage := text[start : start+end]
	for _, phrase := range []string{"proofs/right-edge.json", "index 126", "127-entry", "D13b"} {
		if !strings.Contains(coverage, phrase) {
			t.Errorf("§12.1 does not name the right-edge proof and its boundary: missing %q", phrase)
		}
	}
}

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
	value, err := cbor.DecodeWithin(raw, MaxBundleBytes)
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
	t.Run("index-outside-tree", checkIndexOutsideTreeBundle)
	checkRunFourteenBundlePair(t)
	dir := filepath.Join("..", "..", "testdata", "vectors", "proofs-bad")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatalf("the proof negatives are missing: %v", err)
	}
	var doc struct {
		LogKey string                        `json:"log_key"`
		Cases  []struct{ Name, Says string } `json:"cases"`
		// 6.5l-vi-b-ii-e: the §10.1 code each bundle is refused with. `says`
		// is a semantic hint (§12); where a case names a code, the code is the
		// contract.
		Codes map[string]refusal.Code `json:"codes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 4 {
		t.Fatalf("%d proof negatives; §12.1 names four", len(doc.Cases))
	}
	if len(doc.Codes) != len(doc.Cases) {
		t.Fatalf("%d cases and %d codes: every case names the §10.1 code it is refused with",
			len(doc.Cases), len(doc.Codes))
	}

	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			want, ok := doc.Codes[c.Name]
			if !ok || !refusal.Known(want) {
				t.Fatalf("names %q, which is not a §10.1 code", want)
			}
			body, err := os.ReadFile(filepath.Join(dir, c.Name+".bundle"))
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := Decode(body)
			if err == nil {
				err = bundle.Check(shippedAnchor(t))
			}
			if err == nil {
				t.Fatal("accepted a bundle that proves nothing about this log")
			}
			if got, _ := refusal.CodeOf(err); got != want {
				t.Errorf("refused as %q, and cases.json says %q: %v", got, want, err)
			}
			// The index case's hint quotes SPEC; its dedicated guard above
			// checks the code and index-only repair, independently of prose.
			if c.Name != "index-outside-tree" && !strings.Contains(err.Error(), c.Says) {
				t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.Says)
			}
		})
	}
}

// §10.1's bundle table is an order, and an order is a vector only where some
// file fails two steps and is coded with the earlier one: a reader that runs
// the two the other way round refuses that file too, with the later code.
// Each property below is computed from the shipped bytes, not read from a
// description of them.
func TestTheBundleOrderHasItsVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "proofs-bad")
	var doc struct {
		Codes map[string]refusal.Code `json:"codes"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	anchor := shippedAnchor(t)
	load := func(name string) *Bundle {
		body, err := os.ReadFile(filepath.Join(dir, name+".bundle"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := Decode(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return b
	}
	// The body's origin, read without trusting the note: what a reader that
	// compared origins before checking the signature would compare.
	bodyOrigin := func(b *Bundle) string {
		origin, _, _ := strings.Cut(b.Checkpoint, "\n")
		return origin
	}
	// Whether the inclusion proof chains to the root the bundle's own
	// checkpoint states -- what an inclusion-first reader would check.
	chains := func(b *Bundle) bool {
		body, _, err := note.Split(b.Checkpoint)
		if err != nil {
			return false
		}
		cp, err := tlog.ParseCheckpoint(body)
		if err != nil {
			return false
		}
		return b.Index >= 0 && b.Index < cp.Size &&
			upstream.CheckRecord(b.Proof, cp.Size, cp.Root, b.Index, tlog.LeafHash(b.Entry)) == nil
	}
	aboutItsDevice := func(b *Bundle) bool {
		subject, err := subjectOf(b.Entry)
		return err == nil && subject == b.Device
	}
	for _, order := range []struct {
		name    string
		earlier refusal.Code
		later   func(*Bundle) bool // true when the later step ALSO fails
	}{
		{"log-signature before origin", refusal.LogSignature,
			func(b *Bundle) bool { return bodyOrigin(b) != anchor.Origin }},
		{"quorum before inclusion", refusal.Quorum,
			func(b *Bundle) bool { return !chains(b) }},
		{"inclusion before binding", refusal.Inclusion,
			func(b *Bundle) bool { return !aboutItsDevice(b) }},
	} {
		t.Run(order.name, func(t *testing.T) {
			for name, code := range doc.Codes {
				if code == order.earlier && order.later(load(name)) {
					return
				}
			}
			t.Errorf("no proofs-bad bundle is coded %q while also failing the later "+
				"step, so a reader that runs them the other way round passes every file",
				order.earlier)
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
	return Anchor{Origin: doc.Origin, LogKeys: []string{doc.LogKey}, Policy: doc.Policy}
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

// --- Cold-model gate run 11, defect D14 ---------------------------------
//
// §8.1's condition 3 — "replay of the log up to that checkpoint yields the
// device as `active` with that `wg_pk`" — never says whose `wg_pk`. The
// nearest antecedent is the bundle's, because the whole list is about a
// bundle; the other reading is that replay simply supplies the key and
// condition 3 only asserts `active`.
//
// The fixture separates them and nothing joined the two halves. `proofs/` is
// one bundle per active device, each proving **the entry that made that
// device active** — the enrol. `nas` rotated afterwards at `log/35`, and §5.3
// deliberately leaves `since_index` on the enrol, so the bundle's own entry
// carries the *old* key while the state carries the current one. Under the
// strict reading `nas` fails condition 3 and is dropped; under the other it is
// proven, which is what `proven/cases.json` requires.
//
// `rotate` is routine, so a stale bundle is the normal case for any device
// that has ever changed its WireGuard key: the strict reading drops peers in
// the ordinary course of operation, quietly, while passing every check in the
// suite.

func TestARotatedDevicesBundleProvesEnrolmentNotItsCurrentKey(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	var manifest struct {
		Bundles map[string]struct {
			File        string `json:"file"`
			ProvesIndex int64  `json:"proves_index"`
			BundleWgPk  string `json:"bundle_wg_pk"`
			StateWgPk   string `json:"state_wg_pk"`
			Says        string `json:"says"`
		} `json:"bundles"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "proven", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Bundles) == 0 {
		t.Fatal("`proven/cases.json` joins no bundle to a proven set, so a reader " +
			"that requires the bundle's own `wg_pk` in condition 3 — and therefore " +
			"drops every device that has ever rotated — passes the whole suite")
	}

	stateRaw, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Devices map[string]struct {
			Status     string `json:"status"`
			WgPk       string `json:"wg_pk"`
			SinceIndex int64  `json:"since_index"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(stateRaw, &st); err != nil {
		t.Fatal(err)
	}

	var separating int
	for device, c := range manifest.Bundles {
		t.Run(device, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(c.File)))
			if err != nil {
				t.Fatalf("the manifest names a bundle that does not ship: %v", err)
			}
			b, err := Decode(body)
			if err != nil {
				t.Fatalf("the bundle does not decode: %v", err)
			}
			if b.Index != c.ProvesIndex {
				t.Errorf("the bundle proves index %d, the manifest says %d",
					b.Index, c.ProvesIndex)
			}

			// The key the bundle's own entry carries...
			inBundle := wgKeyOf(t, b.Entry)
			if inBundle != c.BundleWgPk {
				t.Errorf("the bundle's entry carries wg_pk %s, the manifest says %s",
					inBundle, c.BundleWgPk)
			}

			// ...and the key replay yields, which is the one the node installs.
			dev, ok := st.Devices[device]
			if !ok {
				t.Fatalf("`state.json` has no device %q", device)
			}
			if dev.WgPk != c.StateWgPk {
				t.Errorf("the state's wg_pk is %s, the manifest says %s",
					dev.WgPk, c.StateWgPk)
			}
			if dev.Status != "active" {
				t.Errorf("the device is %q, not active, so condition 3 fails for a "+
					"reason other than the key", dev.Status)
			}
			if c.Says == "" {
				t.Error("the case says nothing about which key condition 3 means, " +
					"which is the only thing a reader cannot derive here")
			}

			if inBundle != dev.WgPk {
				separating++
				// This is the whole point of the case: the device must still be
				// proven, on the replayed key.
				if !provenEverywhere(t, root, device) {
					t.Errorf("%s rotated, so its bundle's key and its state key "+
						"differ — and it is missing from a proven set, which is "+
						"the strict reading of condition 3", device)
				}
			}
		})
	}
	if separating == 0 {
		t.Error("no bundle in the manifest carries a key that differs from the " +
			"state's, so none of them separates the two readings of condition 3")
	}
}

// provenEverywhere reports whether the device appears in every `proven/` case.
func provenEverywhere(t *testing.T, root, device string) bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "proven", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name   string   `json:"name"`
			Proven []string `json:"proven"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Cases {
		var found bool
		for _, d := range c.Proven {
			if d == device {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return len(doc.Cases) > 0
}

// wgKeyOf pulls the WireGuard key an entry establishes, as lowercase hex.
func wgKeyOf(t *testing.T, raw []byte) string {
	t.Helper()
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatalf("the bundle's entry does not decode: %v", err)
	}
	if req, ok := env.Body["request"].([]byte); ok {
		inner, err := cbor.Decode(req)
		if err != nil {
			t.Fatalf("the embedded request does not decode: %v", err)
		}
		if m, ok := inner.(map[string]any); ok {
			if pk, ok := m["wg_pk"].([]byte); ok {
				return hex.EncodeToString(pk)
			}
		}
	}
	if pk, ok := env.Body["wg_pk"].([]byte); ok {
		return hex.EncodeToString(pk)
	}
	t.Fatalf("the entry establishes no wg_pk")
	return ""
}

// Cold gate run 12, D20. §8.1 binds a bundle's `device` to "the `device_id`
// the `entry` names -- for an `enroll`, the id inside the embedded request;
// for the other device types, the `device_id` in the body". Every bundle in
// the suite proved an `enroll`, so a reader that checked the binding only for
// enrolments passed it. Computed from the shipped bundles: a `binding`
// negative proving a `rotate`, and one proving a `revoke`, each labelled with
// a device the entry's body does not name.
func TestBindingIsVectoredBeyondEnroll(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "proofs-bad")
	var doc struct {
		Codes map[string]refusal.Code `json:"codes"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for name, code := range doc.Codes {
		if code != refusal.Binding {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name+".bundle"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := Decode(body)
		if err != nil {
			continue
		}
		env, err := entry.Decode(b.Entry)
		if err != nil {
			continue
		}
		if id, _ := env.Body["device_id"].(string); id != "" && id != b.Device {
			found[env.T] = true
		}
	}
	for _, kind := range []string{"rotate", "revoke"} {
		if !found[kind] {
			t.Errorf("no proofs-bad bundle proves a %s entry under another device's label "+
				"and is coded `binding`, so a reader that binds only enrolments passes", kind)
		}
	}
}

// A one-leaf tree has no proof hashes to reject instead of its index. Only
// changing that index may turn this negative into a sound bundle.
func checkIndexOutsideTreeBundle(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors")
	var manifest struct {
		Cases []struct{ Name, Says string }
		Codes map[string]string
	}
	raw, err := os.ReadFile(filepath.Join(dir, "proofs-bad", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, c := range manifest.Cases {
		if c.Name == "index-outside-tree" {
			found++
			if c.Says != "the index is outside the tree" {
				t.Fatal("missing index rule")
			}
		}
	}
	if found != 1 || manifest.Codes["index-outside-tree"] != "inclusion" {
		t.Fatal("missing out-of-tree index case and code")
	}
	raw, err = os.ReadFile(filepath.Join(dir, "proofs-bad", "index-outside-tree.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := tlog.Verify(b.Checkpoint, shippedAnchor(t).LogKeys)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := os.ReadFile(filepath.Join(dir, "log", "1-enroll-nas.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	if cp.Size != 1 || b.Index != 1 || len(b.Proof) != 0 || cp.Root != tlog.LeafHash(b.Entry) || string(b.Entry) != string(leaf) || b.Device != "nas" {
		t.Fatal("case must be nas at index 1 of a one-leaf tree with an empty proof")
	}
	if code, _ := refusal.CodeOf(b.Check(shippedAnchor(t))); code != refusal.Inclusion {
		t.Fatalf("index refusal = %q, want inclusion", code)
	}
	b.Index = 0
	if err := b.Check(shippedAnchor(t)); err != nil {
		t.Fatalf("index-only repair: %v", err)
	}
	t.Log("index 1: inclusion; only index changed to 0: accept")
}
