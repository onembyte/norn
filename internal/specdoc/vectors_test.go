package specdoc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	cborpkg "github.com/onembyte/norn/internal/cbor"
	entrypkg "github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/proof"
	receiptpkg "github.com/onembyte/norn/internal/receipt"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/trust"
)

// The committed vectors are the contract between implementations. Nothing used
// to verify that they still match what the reference implementation produces,
// which is how seven orphan files from a renumbering survived three
// conformance runs. These checks are cheap, need no Python, and run on every
// build.

func vectorRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "vectors")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("vector root: %v", err)
	}
	return root
}

func TestRunThirteenPathAndTrustCaseVectorsAreCited(t *testing.T) {
	doc := load(t)
	index, _ := doc.Section("12")
	coverage, _ := doc.Section("12.1")
	if !strings.Contains(index.Body, "`paths`") || !strings.Contains(index.Body, "`served-large/`") {
		t.Error("§12 must name served-large/cases.json's paths table")
	}
	for _, path := range []string{"served-large/cases.json", "trust-bad/45-origin-case-changed",
		"trust-bad/46-log-key-name-case-changed"} {
		if !strings.Contains(coverage.Body, path) {
			t.Errorf("§12.1 does not cite %s", path)
		}
	}
	var manifest struct {
		Rules map[string]struct {
			Section string `json:"section"`
			Says    string `json:"says"`
		} `json:"rules"`
	}
	readJSON(t, filepath.Join(vectorRoot(t), "trust-bad", "cases.json"), &manifest)
	rule := manifest.Rules["45-origin-case-changed"]
	if rule.Section != "9.1" || rule.Says != "MUST equal `norn/` + lowercase unpadded" {
		t.Errorf("origin-case negative names rule %+v, want §9.1's origin row", rule)
	}
	rule = manifest.Rules["46-log-key-name-case-changed"]
	if rule.Section != "9.1" || rule.Says != "its note name MUST equal `origin`" {
		t.Errorf("log-key-name-case negative names rule %+v, want §9.1's note-name rule", rule)
	}
}

type manifest struct {
	Anchor struct {
		Net         string `json:"net"`
		GenesisHash string `json:"genesis_hash"`
	} `json:"anchor"`
	Entries []struct {
		Index  int    `json:"index"`
		Name   string `json:"name"`
		Reason string `json:"reason"`
	} `json:"entries"`
}

func loadManifest(t *testing.T, path string) manifest {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return m
}

func TestLogHasNoOrphanFiles(t *testing.T) {
	root := vectorRoot(t)
	m := loadManifest(t, filepath.Join(root, "log", "manifest.json"))

	named := map[string]bool{}
	for _, e := range m.Entries {
		named[e.Name] = true
	}
	entries, err := os.ReadDir(filepath.Join(root, "log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range entries {
		name := f.Name()
		if name == "manifest.json" {
			continue
		}
		stem := strings.TrimSuffix(strings.TrimSuffix(name, ".cbor"), ".reason")
		if !named[stem] {
			t.Errorf("log/%s is not named by manifest.json — an orphan sorts between "+
				"live entries and silently corrupts a glob-and-sort reader", name)
		}
	}
}

func TestEveryManifestEntryHasItsFile(t *testing.T) {
	root := vectorRoot(t)
	m := loadManifest(t, filepath.Join(root, "log", "manifest.json"))
	for _, e := range m.Entries {
		path := filepath.Join(root, "log", e.Name+".cbor")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("manifest names %s but %s is missing", e.Name, path)
		}
		if e.Reason == "" {
			continue
		}
		reason := filepath.Join(root, "log", e.Name+".reason")
		got, err := os.ReadFile(reason)
		if err != nil {
			t.Errorf("rejected entry %s has no .reason sidecar", e.Name)
			continue
		}
		if strings.TrimSpace(string(got)) != e.Reason {
			t.Errorf("%s: sidecar says %q, manifest says %q",
				e.Name, strings.TrimSpace(string(got)), e.Reason)
		}
	}
}

func TestEntryNamesAgreeWithTheirIndices(t *testing.T) {
	root := vectorRoot(t)
	m := loadManifest(t, filepath.Join(root, "log", "manifest.json"))
	for _, e := range m.Entries {
		head, _, ok := strings.Cut(e.Name, "-")
		if !ok {
			t.Errorf("entry %d is named %q with no index prefix", e.Index, e.Name)
			continue
		}
		n, err := strconv.Atoi(head)
		if err != nil || n != e.Index {
			t.Errorf("entry %d is named %q; the prefix must be its own index", e.Index, e.Name)
		}
	}
}

func TestGenesisHashInTheManifestIsTheLeafHashOfEntryZero(t *testing.T) {
	root := vectorRoot(t)
	m := loadManifest(t, filepath.Join(root, "log", "manifest.json"))
	raw, err := os.ReadFile(filepath.Join(root, "log", m.Entries[0].Name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte{0x00}, raw...))
	want := m.Anchor.GenesisHash
	if got := hex(sum[:]); got != want {
		t.Errorf("anchor genesis_hash %s but leaf hash of entry 0 is %s", want, got)
	}
}

func hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// TestSpecVectorCitationsResolve guards the failure that broke §12.1 twice:
// the coverage table cited vectors by index, a later insertion shifted every
// index, and the citations silently began naming the wrong entries. Citations
// are by name now, and this fails the build if one stops resolving.
func TestSpecVectorCitationsResolve(t *testing.T) {
	root := vectorRoot(t)
	m := loadManifest(t, filepath.Join(root, "log", "manifest.json"))
	suffixes := map[string]bool{}
	for _, e := range m.Entries {
		if _, rest, ok := strings.Cut(e.Name, "-"); ok {
			suffixes[rest] = true
		}
	}
	// A `bad-` name in §12.1 need not be a *log* entry -- `policies/` and
	// `fork/` carry them too. This matched only the log manifest, which is the
	// same blind spot D7 found in the path checker: a name it could not see
	// was a name it reported nothing about.
	for name := range shippedVectorNames(t) {
		suffixes[name] = true
	}

	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	section := string(spec)
	start := strings.Index(section, "### 12.1")
	end := strings.Index(section, "## 13.")
	if start < 0 || end < 0 {
		t.Fatal("§12.1 not found")
	}

	// §5.2 reason codes share the "bad-" prefix with vector names but are not
	// vectors; listing them keeps the heuristic honest rather than loose.
	reasonCodes := map[string]bool{
		"bad-genesis": true, "bad-thr": true,
	}

	for _, quoted := range backticked(section[start:end]) {
		if !strings.HasPrefix(quoted, "bad-") && !strings.HasSuffix(quoted, "-base") {
			continue
		}
		if reasonCodes[quoted] && !suffixes[quoted] {
			continue
		}
		if !suffixes[quoted] {
			t.Errorf("§12.1 cites vector %q, which no manifest entry matches", quoted)
		}
	}
}

func TestExcessPaddingCoverageDescribesItsDistinguishingShape(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	row := ""
	for _, line := range strings.Split(section.Body, "\n") {
		if strings.Contains(line, "§16.2 padding") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("§12.1 has no padding coverage row")
	}
	for _, phrase := range []string{"req-padding-base", "203-byte", "one zero 5-bit group",
		"six unused bits", "§16.2 alone"} {
		if !strings.Contains(row, phrase) {
			t.Errorf("padding coverage row omits %q: %s", phrase, row)
		}
	}
	if strings.Contains(row, "payload is the valid request with its encoding corrupted") {
		t.Error("padding coverage still claims the old vector is refused by the padding rule")
	}
}

func TestLabelValueCoveragePinsBothUtf8ByteBoundaries(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	row := ""
	for _, line := range strings.Split(section.Body, "\n") {
		if strings.Contains(line, "§4.0 label-value byte cap") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("§12.1 has no label-value byte-cap coverage row")
	}
	for _, phrase := range []string{"req-label-at-cap", "256 UTF-8 bytes", "oversize-label",
		"257-byte value", "character-counting reader accepts it"} {
		if !strings.Contains(row, phrase) {
			t.Errorf("label-value coverage row omits %q: %s", phrase, row)
		}
	}
}

func TestReservedHintSyntaxIsUnvalidatedAndPositivelyCovered(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("4.0")
	if !ok {
		t.Fatal("§4.0 is missing")
	}
	normative := strings.Join(strings.Fields(section.Body), " ")
	for _, phrase := range []string{"hint syntax MUST NOT be validated",
		"MUST NOT by itself invalidate the request", "embedded request in an `enroll` entry",
		"ordinary UTF-8, type, and byte-length constraints still apply"} {
		if !strings.Contains(normative, phrase) {
			t.Errorf("§4.0 does not state %q", phrase)
		}
	}

	coverage, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	for _, phrase := range []string{"requests/req-reserved-hints",
		`ip = "not-a-cidr"`, `endpoint = "not-an-endpoint"`,
		"enroll-unicode-labels", "through replay into `state.json`"} {
		if !strings.Contains(coverage.Body, phrase) {
			t.Errorf("§12.1 does not positively pin malformed hint behavior with %q", phrase)
		}
	}
}

func TestOversizeRequestLabelKeyCoverageNamesTheDecoderLayer(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	row := ""
	for _, line := range strings.Split(section.Body, "\n") {
		if strings.Contains(line, "§4.0 the map-key cap, at the decoder") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("§12.1 has no decoder-level map-key coverage row")
	}
	for _, phrase := range []string{"oversize-label-key", "24-byte label key",
		"decoder before the `labels` field rule"} {
		if !strings.Contains(row, phrase) {
			t.Errorf("map-key coverage row omits %q: %s", phrase, row)
		}
	}
	if strings.Contains(row, "field rule first") {
		t.Errorf("map-key coverage misattributes the request refusal: %s", row)
	}
}

func TestSpecGenesisHashExampleMatchesTrustVector(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("9.2")
	if !ok {
		t.Fatal("§9.2 is missing")
	}
	trust, err := os.ReadFile(filepath.Join(vectorRoot(t), "trust.toml"))
	if err != nil {
		t.Fatal(err)
	}
	hashRE := regexp.MustCompile(`(?m)^genesis_hash\s*=\s*"([0-9a-f]{64})"`)
	trustHash := hashRE.FindSubmatch(trust)
	if len(trustHash) != 2 {
		t.Fatal("trust.toml has no full genesis_hash")
	}
	specHash := hashRE.FindAllSubmatch([]byte(section.Body), -1)
	if len(specHash) != 1 {
		t.Fatalf("§9.2 has %d full genesis_hash examples, want one", len(specHash))
	}
	if string(specHash[0][1]) != string(trustHash[1]) {
		t.Errorf("§9.2's genesis_hash %s differs from trust.toml %s",
			specHash[0][1], trustHash[1])
	}
}

func TestSpecTitleMatchesItsFrozenVersion(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) < 2 {
		t.Fatal("SPEC.md has no title and status")
	}
	if lines[0] != "# Norn — Specification v1" {
		t.Errorf("SPEC title is %q; the frozen document is v1", lines[0])
	}
	preamble := strings.Join(lines[:min(5, len(lines))], " ")
	if !strings.Contains(preamble, "Status: **v1**, frozen") {
		t.Errorf("SPEC preamble does not state the frozen v1 status: %q", preamble)
	}
}

func TestProcedureOrderingListsFiveVectors(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("5.1")
	if !ok {
		t.Fatal("§5.1 is missing")
	}
	body := strings.Join(strings.Fields(section.Body), " ")
	if !strings.Contains(body, "The five vectors that carry the weight are") {
		t.Error("§5.1 does not say that five vectors pin the ordering")
	}
	for _, vector := range []string{
		"log/99-bad-precedence-decode-before-unknown-type",
		"log/100-bad-precedence-decode-before-after",
		"log/101-bad-precedence-after-before-threshold",
		"log/102-bad-precedence-threshold-before-dup-id",
		"log/103-bad-precedence-threshold-before-dup-wg",
	} {
		if !strings.Contains(body, "`"+vector+"`") {
			t.Errorf("§5.1 does not name %s as an ordering vector", vector)
		}
	}
}

func TestTrustCoverageExplainsTheIsolatedWitnessNegatives(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	row := ""
	for _, line := range strings.Split(section.Body, "\n") {
		if strings.Contains(line, "§9.1 four rules that another rule used to decide") {
			row = strings.Join(strings.Fields(line), " ")
			break
		}
	}
	if row == "" {
		t.Fatal("§12.1 has no trust witness-minimum and uniqueness row")
	}
	for _, phrase := range []string{"07-no-witnesses",
		"only the explicit witness minimum can refuse it",
		"08-duplicate-witness-name", "only uniqueness is broken"} {
		if !strings.Contains(row, phrase) {
			t.Errorf("trust coverage row omits why %q is isolated: %s", phrase, row)
		}
	}
}

func TestRun12CoverageFindingsAreNamedOrAdmitted(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	for _, vector := range []string{
		"134-bad-repeated-kid", "bad-held-root-at-same-size",
		"fork-on-a-longer-branch", "tampered-bundle-under-a-stored-head",
		"bad-none-group-member",
		"log/99-bad-precedence-decode-before-unknown-type",
		"log/100-bad-precedence-decode-before-after",
		"log/101-bad-precedence-after-before-threshold",
		"log/102-bad-precedence-threshold-before-dup-id",
		"log/103-bad-precedence-threshold-before-dup-wg",
		"13-origin-only", "receipt-bad/", "served-large/",
		"proofs/right-edge.json", "23-extra-final-newline", "req-padding-base",
		"req-label-at-cap", "bad-size-above-held", "req-reserved-hints",
		"enroll-astral-labels", "rotate-entry-other-device",
	} {
		if !strings.Contains(section.Body, vector) {
			t.Errorf("§12.1 no longer accounts for run 12 coverage finding %q", vector)
		}
	}
}

func TestBooleanProfileAndForkSchemaLayerAreSpecified(t *testing.T) {
	doc := load(t)
	encoding, ok := doc.Section("4.0")
	if !ok {
		t.Fatal("§4.0 is missing")
	}
	encodingText := strings.Join(strings.Fields(encoding.Body), " ")
	for _, phrase := range []string{
		"valid CBOR items; schemas MUST reject them outside `params.rotate_needs_signer`",
	} {
		if !strings.Contains(encodingText, phrase) {
			t.Errorf("§4.0 does not define the boolean profile/schema boundary: missing %q", phrase)
		}
	}
	evidence, ok := doc.Section("11.1")
	if !ok {
		t.Fatal("§11.1 is missing")
	}
	evidenceText := strings.Join(strings.Fields(evidence.Body), " ")
	if !strings.Contains(evidenceText, "the `size` field is a boolean rather than a uint") {
		t.Error("§11.1 does not classify a boolean `size` as a schema refusal")
	}

	coverage, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	row := ""
	for _, line := range strings.Split(coverage.Body, "\n") {
		if strings.Contains(line, "§4.0 booleans are profile items") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("§12.1 has no boolean profile/schema coverage row")
	}
	for _, phrase := range []string{"fork/bad-bool-size.cbor", "valid CBOR", "`schema`"} {
		if !strings.Contains(row, phrase) {
			t.Errorf("boolean coverage row omits %q: %s", phrase, row)
		}
	}
}

func TestQuorumTimePolicyScopeIsExplicit(t *testing.T) {
	doc := load(t)
	for id, phrases := range map[string][]string{
		"5.3": {
			"The policy is the one under which this checkpoint was accepted",
			"A `policy` entry in this checkpoint's replay range MUST NOT change this checkpoint's `T`",
		},
		"9.4": {
			"for every checkpoint a node accepts after replaying it",
			"does not apply retroactively to the checkpoint that carried it",
		},
	} {
		section, ok := doc.Section(id)
		if !ok {
			t.Fatalf("§%s is missing", id)
		}
		body := strings.Join(strings.Fields(section.Body), " ")
		for _, phrase := range phrases {
			if !strings.Contains(body, phrase) {
				t.Errorf("§%s does not resolve the scope of policy for T: missing %q", id, phrase)
			}
		}
	}

	coverage, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	row := ""
	for _, line := range strings.Split(coverage.Body, "\n") {
		if strings.Contains(line, "§5.3 policy for the checkpoint's `T`") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("§12.1 has no coverage row for which policy computes the checkpoint's T")
	}
	for _, phrase := range []string{"proofs/cases.json", "checkpoint_quorum_time",
		"replayed_policy_quorum_time", "1760003607", "1760003600"} {
		if !strings.Contains(row, phrase) {
			t.Errorf("§12.1 quorum-time row omits %q: %s", phrase, row)
		}
	}
}

func backticked(text string) []string {
	var out []string
	for {
		i := strings.Index(text, "`")
		if i < 0 {
			return out
		}
		text = text[i+1:]
		j := strings.Index(text, "`")
		if j < 0 {
			return out
		}
		out = append(out, text[:j])
		text = text[j+1:]
	}
}

// TestSpecFingerprintExampleIsCurrent guards the same failure as the vector
// citations, in the one other place SPEC.md quotes a value from the suite.
//
// It drifted once already: checkpoint 0.13b gave genesis a non-default `mmd`,
// which changed the genesis entry, which changed `genesis_hash`, which is
// inside the trust file -- so the fingerprint moved and the spec's worked
// example silently became fiction. A worked example nobody checks is worse
// than none, because a reader trusts it.
func TestSpecFingerprintExampleIsCurrent(t *testing.T) {
	want, err := os.ReadFile(filepath.Join(vectorRoot(t), "trust.fingerprint"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.TrimSpace(string(want))
	if fingerprint == "" {
		t.Fatal("the shipped fingerprint is empty")
	}

	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(spec), fingerprint) {
		t.Errorf("SPEC.md does not mention the shipped fingerprint %s; its worked "+
			"example has gone stale", fingerprint)
	}
	// And it must not still be quoting a different one.
	for _, line := range strings.Split(string(spec), "\n") {
		if !strings.Contains(line, "fingerprint") && !strings.Contains(line, "-") {
			continue
		}
		for _, field := range strings.Fields(line) {
			trimmed := strings.Trim(field, "`.,()")
			if looksLikeFingerprint(trimmed) && trimmed != fingerprint {
				t.Errorf("SPEC.md quotes fingerprint %q, but the suite ships %q",
					trimmed, fingerprint)
			}
		}
	}
}

// looksLikeFingerprint matches the shape of §9.3: four Crockford groups of four.
func looksLikeFingerprint(s string) bool {
	groups := strings.Split(s, "-")
	if len(groups) != 4 {
		return false
	}
	for _, g := range groups {
		if len(g) != 4 {
			return false
		}
		for _, c := range g {
			if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) {
				return false
			}
		}
	}
	return true
}

// TestSpecLogSizeIsCurrent guards the third instance of the same failure: a
// number copied from the suite into SPEC.md and left behind when the suite
// moved. §12 said the replay fixture was 82 entries while it had been 91 since
// checkpoint 1.x -- stale in exactly the way the fingerprint example was.
func TestSpecLogSizeIsCurrent(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(t), "log", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Entries []struct{} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}

	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("**%d entries**", len(manifest.Entries))
	if !strings.Contains(string(spec), want) {
		t.Errorf("SPEC.md §12 does not say %s; the fixture has %d entries and the "+
			"spec has drifted", want, len(manifest.Entries))
	}
	countRE := regexp.MustCompile(`\*\*(\d+) entries\*\*`)
	for _, m := range countRE.FindAllStringSubmatch(string(spec), -1) {
		if m[0] != want {
			t.Errorf("SPEC.md quotes %s, but the fixture has %d entries", m[0], len(manifest.Entries))
		}
	}
}

// The suite has two provenances (§12): the reference implementation writes
// `trust.cbor`, the Go implementation writes `served/` and `proofs/`. Nothing
// checked that they agreed about the log key -- and until 2.9e-i nothing could
// have noticed, because no verifier checked a checkpoint signature. They were
// signed by different keys for six checkpoints.
func TestTheServedLogIsSignedByTheKeyTheTrustFileNames(t *testing.T) {
	root := vectorRoot(t)
	rawTrust, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := trust.Parse(rawTrust)
	if err != nil {
		t.Fatal(err)
	}

	checkpoint, err := os.ReadFile(filepath.Join(root, "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	cp, err := tlog.Verify(string(checkpoint), []string{anchor.LogKey})
	if err != nil {
		t.Fatalf("the served checkpoint does not verify under trust.cbor's log key: %v", err)
	}
	if cp.Origin != anchor.Origin {
		t.Errorf("the served log's origin is %q, the anchor's is %q", cp.Origin, anchor.Origin)
	}

	// The bundles carry that same checkpoint, so they must check too.
	names, err := filepath.Glob(filepath.Join(root, "proofs", "*.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("no proof bundles in the suite")
	}
	for _, name := range names {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := proof.Decode(raw)
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(name), err)
		}
		if err := bundle.Check(proof.Anchor{Origin: anchor.Origin,
			LogKeys: []string{anchor.LogKey}, Policy: anchor.Policy}); err != nil {
			t.Errorf("%s does not check under trust.cbor: %v", filepath.Base(name), err)
		}
	}
}

// Cold-model gate run 7, defect J7: "§12.1 claims X, and arithmetic disproves
// it". Two more of the table's numbers were stale when this was written -- it
// said 51 rejecting entries where the fixture had 74, and 23 request refusals
// where it had 25 -- because nothing counted them. A coverage table nobody
// checks drifts the moment a vector is added, and §12.1 opens by calling an
// inaccurate coverage claim "the same failure wearing a different hat".
//
// Every countable claim in §12.1 is written as `**N <noun>**` and appears
// below. A number with no entry here is a number that will go stale.
func TestTheCoverageTablesCountsAreCurrent(t *testing.T) {
	root := vectorRoot(t)
	counts := map[string]int{
		"rejecting entries": rejectingEntries(t, root),
		"abort paths":       len(caseNames(t, root, "genesis")),
		"request cases":     len(caseNames(t, root, "requests")),
		"request refusals":  len(caseNames(t, root, "requests-bad")),
		"rejected anchors":  len(caseNames(t, root, "trust-bad")),
		"proof refusals":    len(caseNames(t, root, "proofs-bad")),
	}

	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`\*\*(\d+) ([a-z ]+)\*\*`).
		FindAllStringSubmatch(string(spec), -1) {
		want, known := counts[m[2]]
		if !known {
			continue
		}
		seen[m[2]] = true
		if got, _ := strconv.Atoi(m[1]); got != want {
			t.Errorf("§12.1 says %q; the suite has %d", m[0], want)
		}
	}
	for noun := range counts {
		if !seen[noun] {
			t.Errorf("§12.1 no longer states a count of %s, so this check guards nothing", noun)
		}
	}
}

func rejectingEntries(t *testing.T, root string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "log", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Entries []struct {
			Reason string `json:"reason"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range m.Entries {
		if e.Reason != "" {
			n++
		}
	}
	return n
}

// caseNames is the `cases` array of a directory's manifest, whose elements are
// bare strings in some directories and objects in others.
func caseNames(t *testing.T, root, dir string) []json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatalf("%s/cases.json lists nothing", dir)
	}
	return doc.Cases
}

// --- Cold-model gate run 8, defects D1 and D2 ---------------------------
//
// §10 is the only normative *procedure* in this document, and both of its
// ordering bugs were invisible to every test here: the code had the right
// order, the vectors demanded the right order, and the prose that tells a
// second implementer what to do had the wrong one, twice.
//
// D1 is the serious half. §10 opened with `require cp.size >= stored_cp.size`,
// so a reader following the prose answers *refuse* for
// `detect/fork-on-a-shorter-branch`, where `cases.json` demands *fork*. The
// literal reading files a forking log's shorter divergent branch as an
// ordinary rollback: no evidence written, no alarm raised. That is the exact
// case `detect/` exists to catch, and the paragraph describing it said the
// opposite.
//
// Both checks look at the *order of the steps*, keyed on code-like tokens
// rather than on wording, so the prose can be rewritten freely and cannot be
// reordered quietly.

// verifierProcedure is §10's fenced pseudocode block.
func verifierProcedure(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	spec := string(raw)
	head := strings.Index(spec, "\n## 10.")
	if head < 0 {
		t.Fatal("SPEC.md has no §10")
	}
	open := strings.Index(spec[head:], "```")
	if open < 0 {
		t.Fatal("§10 has no pseudocode block")
	}
	body := spec[head+open+3:]
	end := strings.Index(body, "```")
	if end < 0 {
		t.Fatal("§10's pseudocode block is unterminated")
	}
	return body[:end]
}

// mustOrder requires `first` to appear before `second`, and both to appear.
func mustOrder(t *testing.T, block, first, second, why string) {
	t.Helper()
	i, j := strings.Index(block, first), strings.Index(block, second)
	switch {
	case i < 0:
		t.Errorf("§10 no longer contains %q, so its order is not what the vectors "+
			"require: %s", first, why)
	case j < 0:
		t.Errorf("§10 no longer contains %q: %s", second, why)
	case i > j:
		t.Errorf("§10 puts %q before %q. %s", second, first, why)
	}
}

func TestTheVerifierProcedureComparesRootsBeforeApplyingTheSizeRule(t *testing.T) {
	block := verifierProcedure(t)
	mustOrder(t, block, "min(cp.size, stored_cp.size)", "cp.size < stored_cp.size",
		"A log that forks onto a SHORTER branch is refused as a rollback under the "+
			"size-first reading, so no evidence is written and no alarm is raised -- "+
			"`detect/fork-on-a-shorter-branch` demands `fork`, not `refuse`.")
	if !strings.Contains(block, "FORK") {
		t.Error("§10's stored-checkpoint block never reaches FORK, which is the whole " +
			"of what it is for")
	}
}

// §12.1 says `served/` is verified "signature first", and
// `proofs-bad/cases.json` requires `foreign-checkpoint` to be refused about a
// missing trusted signature rather than about its origin. §10 checked the
// origin first, which contradicts both.
func TestTheVerifierProcedureChecksTheSignatureBeforeTheOrigin(t *testing.T) {
	block := verifierProcedure(t)
	mustOrder(t, block, "verify log signature", "cp.origin == norn.trust.origin",
		"A checkpoint signed by a key this anchor does not trust must be refused for "+
			"that, whatever origin it names -- `proofs-bad/foreign-checkpoint` says so, "+
			"and §12.1 calls the loop `signature first`.")
}

// Cold-model gate run 8, defect D6. The vectors README told a reader to start
// with `checkpoints-bad/` because "`04` and `08` are the only files a verifier
// which never checks a signature will accept". That was true when it was
// written and false from the moment `11` was added, and again when `12` was.
// The set is generated now; this checks the sentence against it, so the two
// cannot drift apart again.
func TestTheSignatureBlindClaimNamesTheRightFiles(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(t), "checkpoints-bad", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Blind []string `json:"signature_blind_accepts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Blind) == 0 {
		t.Fatal("cases.json no longer says which files a signature-blind verifier accepts")
	}

	readme, err := os.ReadFile(filepath.Join(vectorRoot(t), "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	// The claim lives in the `checkpoints-bad/` row and nowhere else, so that
	// is where it is read from: scanning the whole file made a number in an
	// unrelated row — `genesis/`'s two halves of entry-0 step 7 — look like a
	// blind-accept claim.
	row := readmeRow(t, string(readme), "`checkpoints-bad/`")

	// The sentence names them by their numeric prefix.
	for _, name := range doc.Blind {
		prefix, _, _ := strings.Cut(name, "-")
		if !strings.Contains(row, "`"+prefix+"`") {
			t.Errorf("a signature-blind verifier accepts %s and the vectors README "+
				"does not name `%s`", name, prefix)
		}
	}
	// ...and names no others.
	listed := map[string]bool{}
	for _, name := range doc.Blind {
		prefix, _, _ := strings.Cut(name, "-")
		listed[prefix] = true
	}
	for _, other := range caseNames(t, vectorRoot(t), "checkpoints-bad") {
		var name string
		if err := json.Unmarshal(other, &name); err != nil {
			continue
		}
		prefix, _, _ := strings.Cut(name, "-")
		if listed[prefix] {
			continue
		}
		if strings.Contains(row, "`"+prefix+"` and") ||
			strings.Contains(row, "and `"+prefix+"`") {
			t.Errorf("the vectors README lists `%s` among the files a signature-blind "+
				"verifier accepts; it does not", prefix)
		}
	}
}

// readmeRow returns the single line of the vectors README describing one
// directory. A claim about one directory is checked against that directory's
// row, never against the whole file.
func readmeRow(t *testing.T, readme, marker string) string {
	t.Helper()
	for _, line := range strings.Split(readme, "\n") {
		if strings.HasPrefix(line, "| "+marker) {
			return line
		}
	}
	t.Fatalf("the vectors README has no row for %s", marker)
	return ""
}

// --- Cold-model gate run 8, defects D3 and D4 ---------------------------
//
// Two things the vectors demand that the document never defined.
//
// D3: §4.0 says a bundle, a trust file and fork evidence "each state their own
// bound", and §8.1 says "the bound is this artifact's, not the entry's". No
// section gives a number. `bundle-entry-size-limit`, `trust-entry-size-limit`
// and an unbounded baseline all passed the whole suite, so all three are
// conforming — which is the same as having no rule.
//
// D4: `detect/staleness.json` demands `fresh`/`degraded`/`hard_stale`/
// `unknown` and supplies an `S_hard`. §8.1's condition 4 is binary, §5.3 never
// names `unknown`, and §15 deferred the ladder to `GOSSIP.md`, which does not
// ship with the vectors. Run 8 got it right only because the vector file
// carries the labels.

func TestEveryArtifactBoundIsStatedAndCurrent(t *testing.T) {
	text := specText(t)
	for _, c := range []struct {
		name  string
		bytes int
		why   string
	}{
		{"MAX_BUNDLE_BYTES", proof.MaxBundleBytes,
			"a bundle wraps an entry that may itself be MAX_ENTRY_BYTES"},
		{"MAX_TRUST_BYTES", trust.MaxTrustBytes, "a trust file"},
		{"MAX_EVIDENCE_BYTES", forkevidence.MaxEvidenceBytes, "fork evidence"},
	} {
		want := fmt.Sprintf("**`%s` is %d**", c.name, c.bytes)
		if !strings.Contains(text, want) {
			t.Errorf("SPEC.md does not say %q. §4.0 promises that %s states its own "+
				"bound, and an unstated bound is one every reader picks differently",
				want, c.why)
		}
	}
}

// The ladder has to be in this document, because `detect/staleness.json` ships
// beside it and expects these four words. A reader given the suite and the
// specification must be able to reproduce the table without `GOSSIP.md`.
func TestTheFreshnessLadderIsDefinedHere(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(t), "detect", "staleness.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hard  int64                     `json:"hard"`
		Cases []struct{ Expect string } `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	text := specText(t)
	seen := map[string]bool{}
	for _, c := range doc.Cases {
		if seen[c.Expect] {
			continue
		}
		seen[c.Expect] = true
		// A row of the ladder, not merely the word somewhere in the
		// document: the first version of this check passed with the row
		// deleted, because `hard_stale` also appears in the prose around it.
		if !strings.Contains(text, "| `"+c.Expect+"` |") {
			t.Errorf("`detect/staleness.json` expects the state %q and SPEC.md's "+
				"ladder has no row for it, so a reader holding only the suite cannot "+
				"reproduce the table", c.Expect)
		}
	}
	if len(seen) < 4 {
		t.Errorf("the vector exercises %d states; the ladder has four", len(seen))
	}
	// And the parameter that separates the last two rungs has to be stated as
	// node-local and opt-in: a reader that takes it from the log's `params`
	// would drop every peer on a network that never configured one.
	if !strings.Contains(text, "`S_hard` is the node's own and is opt-in") {
		t.Error("SPEC.md does not say that S_hard is node-local and opt-in, which is " +
			"what decides `degraded` from `hard_stale` and what keeps an unreachable " +
			"log from taking a network down by itself")
	}
}

// --- Cold-model gate run 8, defect D27 ----------------------------------
//
// The preamble lists the specifications Norn reuses "verbatim; where they
// conflict with this document, they win". Three the document depends on were
// not in it: BIP-350 (§16.2 cites it once and states only Norn's choices
// within it — no charset, no HRP expansion, no polymod, no separator rule, no
// checksum length), RFC 4648 (named in §2 and §9.1, alphabet never given,
// while §9.3 gives Crockford's in full), and RFC 6962's proof-verification
// subsections — §11.1's consistency `proof` carried no citation at all.
//
// Run 8 implemented all three from prior knowledge and said so. A rule a
// reader has to already know is a rule this document failed to state.

func TestThePreambleNamesEveryExternalSpecTheBodyUses(t *testing.T) {
	text := specText(t)
	// The preamble is everything before §1.
	end := strings.Index(text, "\n## 1.")
	if end < 0 {
		t.Fatal("SPEC.md has no §1, so the preamble cannot be bounded")
	}
	preamble := text[:end]

	external := regexp.MustCompile(`BIP-\d+|RFC \d+|c2sp\.org/[a-z-]+`)
	seen := map[string]bool{}
	for _, ref := range external.FindAllString(text[end:], -1) {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		if !strings.Contains(preamble, ref) {
			t.Errorf("the body depends on %s and the preamble never names it. A "+
				"reader who does not already know that specification cannot tell it "+
				"is needed, which is how it gets implemented from memory instead.", ref)
		}
	}
	if len(seen) < 8 {
		t.Errorf("found %d external references in the body; the scan is not working",
			len(seen))
	}
}

// §16.2 and §11.1 are the two places run 8 had to supply an algorithm the
// document names but does not give. Each must say so, and say where it comes
// from, or a reader who does not recognise the name writes their own.
func TestTheBorrowedAlgorithmsSayWhereTheyComeFrom(t *testing.T) {
	doc := load(t)
	// Scoped to the section that needs it, not to the document. The first
	// version of this check looked everywhere, so deleting §11.1's citation
	// left it green -- the preamble still named the RFC. Presence somewhere is
	// not the same as a citation where a reader is standing.
	for _, c := range []struct{ section, needle, why string }{
		{"16.2", "everything else in the encoding is BIP-350's",
			"the section states only Norn's choices — HRP, constant, padding, case — " +
				"and reads as though that is all of it"},
		{"11.1", "RFC 6962 §2.1.2",
			"the `proof` field named a consistency proof and cited nothing, so its " +
				"algorithm and its node ordering were a reader's to guess"},
		{"2", "abcdefghijklmnopqrstuvwxyz234567",
			"§9.3 gives Crockford's alphabet in full and this one was never given"},
	} {
		section, ok := doc.Section(c.section)
		if !ok {
			t.Errorf("§%s is missing", c.section)
			continue
		}
		if !strings.Contains(section.Body, c.needle) {
			t.Errorf("§%s does not state %q — %s", c.section, c.needle, c.why)
		}
	}
}

// --- Cold-model gate run 9, defects D1–D5 -------------------------------
//
// Five rules were added to both implementations and given vectors that demand
// them, and written down in §12.1's **coverage** table rather than in the
// normative section that owns them. A reader of §9.1 or §11.1 cannot derive
// any of the five; run 9 got three right only because the vector is named
// after the rule, which is reverse-engineering from filenames.
//
// §12.1 describes what the suite covers. It is not where a rule lives. This
// test makes "stated where a reader will look" a checked property for every
// rule a vector demands, so the next one cannot be filed in the wrong place.

func TestEveryVectoredRuleIsStatedWhereItLives(t *testing.T) {
	doc := load(t)
	for _, c := range []struct{ section, needle, vector string }{
		{"9.1", "a witness `name` is 1–64 bytes",
			"trust-bad/32-witness-name-too-long"},
		{"9.1", "URL is non-empty",
			"trust-bad/33-log-url-empty-string"},
		{"9.1", "an unknown `type` is ignored",
			"trust-good/anchor-unknown-type and trust-bad/35-anchor-unknown-mode"},
		{"9.1", "it MUST be `norn.trust.log_key`",
			"trust-bad/36-policy-log-key-mismatch"},
		{"11.1", "not above `held`'s own size",
			"fork/bad-size-above-held"},
		// Cold gate run 10, D1-D5: five more rules added to both
		// implementations in this session, given vectors, and written up in
		// §12.1's coverage table rather than the section that owns them.
		{"5.1", "`params`, if present, is **non-empty**",
			"genesis/17-params-empty"},
		{"7", "including the last, ends in one",
			"checkpoints-bad/14-unterminated-signature-block"},
		{"6", "no leading zeroes",
			"checkpoints-bad/15-size-leading-zero"},
		{"10", "Every signature line whose name and key id match",
			"checkpoints-bad/16-two-log-signatures"},
		{"8.1", "`device` is the `device_id` the `entry` names",
			"proofs-bad/device-not-in-entry"},
		// Cold gate run 11, D1: the freshness table's rows overlap, and only
		// their order says which one wins.
		{"8.1", "**first row, read top to bottom, whose condition holds**",
			"detect/staleness.json hard-below-staleness-still-fresh"},
		// D14: condition 3's "that wg_pk" had no antecedent, and one reading
		// drops every peer that has rotated.
		{"8.1", "**the `wg_pk` replay gives**", "proofs/cases.json installs"},
	} {
		t.Run(c.vector, func(t *testing.T) {
			section, ok := doc.Section(c.section)
			if !ok {
				t.Fatalf("§%s is missing", c.section)
			}
			if !strings.Contains(section.Body, c.needle) {
				t.Errorf("§%s does not state %q, and %s is refused for it. A rule a "+
					"vector demands and the normative section omits is a rule a second "+
					"implementer cannot derive -- §12.1 records coverage, not rules.",
					c.section, c.needle, c.vector)
			}
		})
	}
}

// --- Cold-model gate run 9, defect D6 -----------------------------------
//
// `signature_blind_accepts` is *generated* and its contents were
// *hand-written*: the guard added in 6.5i-ii asserts every listed name is a
// real case and never computes the set. So adding `16-two-log-signatures` --
// whose only defect is a signature that does not verify -- silently falsified
// the claim that those five are the set "and nothing else here".
//
// This computes it. A reader that never calls Ed25519 sees exactly the note's
// body and the *names* on its signature lines, so a case is blind-accepted iff
// its body is byte-identical to the honest checkpoint's and the witnesses it
// names still satisfy the policy. No list to keep in step.
func TestTheSignatureBlindSetIsComputedNotAsserted(t *testing.T) {
	root := vectorRoot(t)
	honest, err := os.ReadFile(filepath.Join(root, "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	anchor := shippedTrust(t, root)
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		t.Fatal(err)
	}
	logKey, err := note.ParseVerifierKey(anchor.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]bool{}
	for _, w := range rules.Witnesses {
		named[w.Name] = true
	}
	// The listed witnesses' key ids, by note name: §7's matched-key length
	// rule holds for a witness's 0x04 key as it does for the log's 0x01 key,
	// and checking it needs no signature (SEC-027, checkpoints-bad/28).
	witnessIDs := map[string][]string{}
	for _, key := range rules.Keys() {
		v, err := note.ParseVerifierKey(key)
		if err != nil {
			t.Fatal(err)
		}
		witnessIDs[v.Name] = append(witnessIDs[v.Name], string(v.ID()))
	}

	// blindly reads a note the way a reader that checks no signature does --
	// and no other way. "Blind" means it never calls Ed25519; it still enforces
	// §7's framing and the matched key's public algorithm length, so
	// `14-unterminated-signature-block` is refused by such a reader and is not
	// part of this set. Modelling blind as "ignores the note format too" put it
	// in, which would have been a wrong answer arrived at by a computation
	// rather than by a stale list -- no better.
	blindly := func(text string) (body string, who []string) {
		if !utf8.ValidString(text) {
			return "", nil
		}
		body, block, found := strings.Cut(text, "\n\n")
		if !found || !strings.HasSuffix(block, "\n") {
			return "", nil
		}
		// A block has exactly one final LF. Remove only that terminator, so an
		// extra blank line remains an empty framing line and is refused.
		block = strings.TrimSuffix(block, "\n")
		for _, line := range strings.Split(block, "\n") {
			rest, ok := strings.CutPrefix(line, "— ")
			if !ok {
				return "", nil // unparseable framing: refused without any signature
			}
			// The payload's encoding and its key id need no key, so a blind
			// reader still enforces them: §7 makes the base64 standard and
			// padded and the decoded payload at least a 4-byte key id, and
			// `18` and `19` break one of those each; D14a's nonzero pad-bit
			// cases are also malformed framing. `20`'s length is the log
			// key's to judge, below (D-074 c). Leaving either group out of
			// the model would put cases no conforming reader accepts in this
			// set.
			name, blob, ok := strings.Cut(rest, " ")
			if !ok {
				return "", nil
			}
			raw, err := base64.StdEncoding.Strict().DecodeString(blob)
			if err != nil || base64.StdEncoding.EncodeToString(raw) != blob || len(raw) < 4 {
				return "", nil
			}
			if name == logKey.Name && string(raw[:4]) == string(logKey.ID()) && len(raw) != 68 {
				return "", nil
			}
			for _, id := range witnessIDs[name] {
				if string(raw[:4]) == id && len(raw) != 76 {
					return "", nil
				}
			}
			who = append(who, rules.Label(name))
		}
		return body + "\n", who
	}
	wantBody, _ := blindly(string(honest))

	computed := map[string]bool{}
	for _, name := range checkpointCaseNames(t, root) {
		raw, err := os.ReadFile(filepath.Join(root, "checkpoints-bad", name+".checkpoint"))
		if err != nil {
			t.Fatal(err)
		}
		body, who := blindly(string(raw))
		if body == wantBody && rules.Satisfied(who) {
			computed[name] = true
		}
	}

	listed := map[string]bool{}
	for _, name := range signatureBlindAccepts(t, root) {
		listed[name] = true
	}
	for name := range computed {
		if !listed[name] {
			t.Errorf("a signature-blind reader accepts %s and `signature_blind_accepts` "+
				"does not list it; the claim says those are the set and nothing else", name)
		}
	}
	for name := range listed {
		if !computed[name] {
			t.Errorf("`signature_blind_accepts` lists %s and a signature-blind reader "+
				"refuses it", name)
		}
	}
	if len(computed) == 0 {
		t.Error("no case is blind-accepted, so this computes nothing")
	}
}

func checkpointCaseNames(t *testing.T, root string) []string {
	t.Helper()
	var doc struct {
		Cases []string `json:"cases"`
	}
	readJSON(t, filepath.Join(root, "checkpoints-bad", "cases.json"), &doc)
	return doc.Cases
}

func signatureBlindAccepts(t *testing.T, root string) []string {
	t.Helper()
	var doc struct {
		Blind []string `json:"signature_blind_accepts"`
	}
	readJSON(t, filepath.Join(root, "checkpoints-bad", "cases.json"), &doc)
	return doc.Blind
}

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

func shippedTrust(t *testing.T, root string) *trust.Trust {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// --- Cold-model gate run 10: why D1–D5 recurred -------------------------
//
// The table above is a *list*. It maps five, now ten, named rules to phrases
// their sections must contain — and it cannot notice an eleventh, because
// nothing obliges a new vector to declare which section states its rule. Run
// 9 found five such rules, I added the list, and run 10 found five more. A
// list is not an invariant.
//
// This is the invariant: every case in a manifest that carries `rules` must
// name the section that states its rule and a phrase that appears there. The
// generator writes `rules` beside `cases`, so a vector cannot be added
// without answering the question — and a directory listed here that stops
// carrying `rules` fails too, which stops the mechanism being quietly dropped.

func TestEveryNegativeDeclaresTheSectionThatStatesItsRule(t *testing.T) {
	doc := load(t)
	root := vectorRoot(t)
	// The directories whose rules run 10 found missing. The rest are named in
	// BUILD-LOG 6.5k-i-b; a directory joins this list when its manifest grows
	// a `rules` map, and can never leave it.
	for _, dir := range []string{
		"checkpoints-bad", "proofs-bad", "served-bad", "fork",
		"entries-hostile", "policies", "genesis", "trust-bad", "receipt-bad", "requests-bad",
		"served-genesis", "log-cas", "log-edges",
	} {
		t.Run(dir, func(t *testing.T) {
			var manifest struct {
				Cases   json.RawMessage `json:"cases"`
				Entries []struct {
					Name   string
					Reason string
				} `json:"entries"`
				Rules map[string]struct {
					Section string `json:"section"`
					Says    string `json:"says"`
				} `json:"rules"`
			}
			file := "cases.json"
			if dir == "log-cas" || dir == "log-edges" {
				file = "manifest.json"
			}
			readJSON(t, filepath.Join(root, dir, file), &manifest)
			if len(manifest.Rules) == 0 {
				t.Fatalf("%s/cases.json carries no `rules` map. Every negative must "+
					"name the section that states the rule it is about, or the rule "+
					"can live in §12.1 and nowhere a reader will look.", dir)
			}
			for name, rule := range manifest.Rules {
				section, ok := doc.Section(rule.Section)
				if !ok {
					t.Errorf("%s names §%s, which does not exist", name, rule.Section)
					continue
				}
				if rule.Says == "" {
					t.Errorf("%s names §%s and no phrase; a section reference without "+
						"one cannot show the rule is written there", name, rule.Section)
					continue
				}
				if !strings.Contains(section.Body, rule.Says) {
					t.Errorf("%s is refused by a rule §%s does not state: %q",
						name, rule.Section, rule.Says)
				}
			}
			// ...and every case must appear in it, so adding one forces the answer.
			// A `cases` array is bare strings in some manifests and objects in
			// others. A failed unmarshal into []string leaves the slice
			// populated with empties, so the fallback starts from nil.
			var names []string
			if dir == "log-cas" || dir == "log-edges" {
				for _, e := range manifest.Entries {
					if e.Reason != "" {
						names = append(names, e.Name)
					}
				}
			} else if err := json.Unmarshal(manifest.Cases, &names); err != nil {
				names = nil
				var objs []struct{ Name string }
				if err := json.Unmarshal(manifest.Cases, &objs); err != nil {
					t.Fatal(err)
				}
				for _, o := range objs {
					names = append(names, o.Name)
				}
			}
			for _, name := range names {
				if _, ok := manifest.Rules[name]; !ok {
					t.Errorf("%s has no entry in `rules`, so nothing says which section "+
						"states the rule that refuses it", name)
				}
			}
		})
	}
}

// --- Cold-model gate run 10, defects D7 and D8 --------------------------
//
// Two encoding-profile rules a reader could hold the narrow half of and pass
// all 236 checks. Both are prose defects with a behavioural consequence, so
// both get a guard here and a vector in `internal/cbor`.

func TestTheShortestFormRuleIsStatedForEveryArgumentNotJustIntegers(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("4.0")
	if !ok {
		t.Fatal("§4.0 is missing")
	}
	// The rule lived in the **Integers** row of a table that enumerates
	// requirements field by field, which is what a reader implements from. RFC
	// 8949 §4.2.1 requires the preferred form of every head's argument; the
	// table has to say so, because the reader is reading the table.
	for _, needle := range []string{
		"every argument",
		"length header",
	} {
		if !strings.Contains(section.Body, needle) {
			t.Errorf("§4.0 does not say %q, so the shortest-form rule reads as being "+
				"about integers alone — and under that reading one logical entry has "+
				"several legal encodings, which is two leaves that both replay", needle)
		}
	}
}

func TestMapKeyOrderIsStatedAsStrictlyIncreasing(t *testing.T) {
	doc := load(t)
	for _, number := range []string{"4.0", "4.1"} {
		section, ok := doc.Section(number)
		if !ok {
			t.Fatalf("§%s is missing", number)
			continue
		}
		if !strings.Contains(section.Body, "strictly increasing") {
			t.Errorf("§%s does not say keys are **strictly increasing**. Stated as "+
				"\"sorted\" plus a separate \"no duplicate keys\", each rule hides the "+
				"gap in the other and a reader who holds the lax half of both — "+
				"non-decreasing order, last key wins — accepts a duplicated key",
				number)
		}
	}
}

// --- Cold-model gate run 10, defects D9 and D10 -------------------------
//
// Both are §9.1's restated `tlog-policy` grammar, and both are the same
// failure: a rule the parser enforces, the vectors depend on, and the prose
// never contains.

func TestThePolicyGrammarBoundsEachDirectivesFieldCount(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("9.1")
	if !ok {
		t.Fatal("§9.1 is missing")
	}
	if !strings.Contains(section.Body, "field count") {
		t.Error("§9.1 never bounds a directive's field count — and that unstated rule " +
			"is what was refusing the whitespace negatives, so the rule the section " +
			"states in bold was pinned by nothing")
	}
}

func TestThePolicyCommentRuleSaysWhereAHashIsNotAComment(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("9.1")
	if !ok {
		t.Fatal("§9.1 is missing")
	}
	// "First non-space character" is the one rule in that table that does not
	// say "space or tab", and it says nothing at all about a `#` further along
	// the line. Three readings survived it.
	for _, needle := range []string{
		"first character other than ASCII space or tab",
		"an ordinary character",
	} {
		if !strings.Contains(section.Body, needle) {
			t.Errorf("§9.1 does not say %q, so a tab-indented comment and a trailing "+
				"`#` are both a reader's to guess", needle)
		}
	}
}

// --- Cold-model gate run 10, defect D11 ---------------------------------
//
// Three checks on a served log, two of them individually unpinned. The
// rebuild-vs-head comparison gets a vector of its own in `cmd/norn`; the root
// line's length gets one here; and §10's "never from a supplied proof" gets
// the only honest treatment left, which is to be written down as unvectored.

func TestTheRootLinesLengthIsStatedAndVectored(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("6")
	if !ok {
		t.Fatal("§6 is missing")
	}
	if !strings.Contains(section.Body, "32 bytes once decoded") {
		t.Error("§6 does not bound the checkpoint's root line, so a reader that " +
			"accepts any base64 there is reading a conforming document")
	}
	var manifest struct {
		Cases []string `json:"cases"`
		Rules map[string]struct{ Section, Says string }
	}
	readJSON(t, filepath.Join(vectorRoot(t), "checkpoints-bad", "cases.json"), &manifest)
	var found string
	for _, name := range manifest.Cases {
		if strings.Contains(name, "root-wrong-length") {
			found = name
		}
	}
	if found == "" {
		t.Fatal("no `checkpoints-bad` case carries a root line of the wrong length, so " +
			"the rule is stated and reachable by nothing")
	}
	if rule := manifest.Rules[found]; rule.Section != "6" {
		t.Errorf("%s names §%s; the root line's length is §6's rule", found, rule.Section)
	}
}

func TestTheSuppliedProofClauseIsAdmittedAsUnvectored(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	// §10 says the served branch's root at `at` is "recomputed from the
	// entries, never from a supplied proof". No vector supplies a proof there
	// — a fork comparison takes its roots from the tiles — so a reader that
	// honoured a supplied one passed everything. It is a real rule and this
	// suite cannot reach it; §12.1's own standard is that such a rule is named
	// rather than left to look covered.
	if !strings.Contains(section.Body, "never from a supplied proof") {
		t.Error("§12.1's `What is not vectored` list does not mention §10's " +
			"`never from a supplied proof` clause, which no shipped file exercises")
	}
}

// --- Cold-model gate run 10, defect D13 ---------------------------------
//
// §7 restates the signed-note framing "so an implementer needs nothing else"
// and left five splits to the reader. Three get a vector; two cannot have one
// and §12.1 now says why.

func TestTheNoteFramingDecidesItsFiveSplits(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("7")
	if !ok {
		t.Fatal("§7 is missing")
	}
	for _, c := range []struct{ needle, why string }{
		{"the **first** blank line ends the text",
			"a reader ending it at the last blank line signs a different string"},
		{"contains no space",
			"a key name with a space is the only thing that separates splitting the " +
				"line at its first space from splitting it at its last"},
		{"standard base64 **with padding**",
			"unpadded base64 decodes to the same bytes, so two readers disagree " +
				"about which lines are well-formed and about nothing else"},
		{"**exactly**",
			"a payload longer than its algorithm's length still verifies under a " +
				"prefix-reading verifier, so one head has unboundedly many " +
				"byte-distinct forms that are all valid"},
		{"at least one signature line",
			"a note with none is not a signed note"},
	} {
		if !strings.Contains(section.Body, c.needle) {
			t.Errorf("§7 does not say %q — %s", c.needle, c.why)
		}
	}
}

func TestTheThreeSeparableFramingRulesAreVectored(t *testing.T) {
	var manifest struct {
		Cases []string `json:"cases"`
		Rules map[string]struct{ Section, Says string }
	}
	readJSON(t, filepath.Join(vectorRoot(t), "checkpoints-bad", "cases.json"), &manifest)
	// The payload length was the third framing rule until D-074 (c) gave it
	// to the matched key: framing takes every length from a key id up, and
	// the log's key refuses its own line one byte long, as §10's step.
	for suffix, section := range map[string]string{
		"-signature-name-with-space":  "7",
		"-signature-unpadded-base64":  "7",
		"-signature-payload-too-long": "10",
	} {
		var found string
		for _, name := range manifest.Cases {
			if strings.HasSuffix(name, suffix) {
				found = name
			}
		}
		if found == "" {
			t.Errorf("no `checkpoints-bad` case *%s, so §7's rule is stated and "+
				"reachable by nothing", suffix)
			continue
		}
		if rule := manifest.Rules[found]; rule.Section != section {
			t.Errorf("%s names §%s; its rule is §%s's", found, rule.Section, section)
		}
	}
}

func TestCanonicalBase64PadBitsAreSpecifiedAndVectored(t *testing.T) {
	doc := load(t)
	for sectionNumber, label := range map[string]string{
		"6": "checkpoint root",
		"7": "signed-note payload",
	} {
		section, ok := doc.Section(sectionNumber)
		if !ok {
			t.Fatalf("§%s is missing", sectionNumber)
		}
		for _, phrase := range []string{"RFC 4648 §3.5", "unused pad bits MUST be zero"} {
			if !strings.Contains(section.Body, phrase) {
				t.Errorf("§%s does not state canonical base64 for the %s: missing %q",
					sectionNumber, label, phrase)
			}
		}
	}

	var manifest struct {
		Cases []string          `json:"cases"`
		Codes map[string]string `json:"codes"`
		Rules map[string]struct {
			Section string `json:"section"`
			Says    string `json:"says"`
		} `json:"rules"`
	}
	readJSON(t, filepath.Join(vectorRoot(t), "checkpoints-bad", "cases.json"), &manifest)
	want := map[string]struct{ code, section string }{
		"25-signature-nonzero-pad-bits":   {"note", "7"},
		"26-cosignature-nonzero-pad-bits": {"note", "7"},
		"27-root-nonzero-pad-bits":        {"checkpoint", "6"},
	}
	seen := map[string]bool{}
	for _, name := range manifest.Cases {
		if rule, ok := want[name]; ok {
			seen[name] = true
			if manifest.Codes[name] != rule.code {
				t.Errorf("%s is refused as %q, want %q", name, manifest.Codes[name], rule.code)
			}
			if got := manifest.Rules[name].Section; got != rule.section {
				t.Errorf("%s cites §%s, want §%s", name, got, rule.section)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("checkpoints-bad/cases.json does not name %s", name)
		}
	}
	coverage, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	for name := range want {
		if !strings.Contains(coverage.Body, "checkpoints-bad/"+name) {
			t.Errorf("§12.1 does not cite checkpoints-bad/%s", name)
		}
	}
}

func TestVerifierKeyCanonicalBase64UsesTheActualKeyLength(t *testing.T) {
	doc := load(t)
	for _, sectionNumber := range []string{"7", "9.1"} {
		section, ok := doc.Section(sectionNumber)
		if !ok {
			t.Fatalf("§%s is missing", sectionNumber)
		}
		if !strings.Contains(section.Body, "verifier-key data MUST be canonical RFC 4648 base64") {
			t.Errorf("§%s does not require canonical verifier-key data", sectionNumber)
		}
	}
	noteSection, _ := doc.Section("7")
	if !strings.Contains(noteSection.Body, "33 bytes encode to 44 base64 characters without padding") {
		t.Error("§7 does not explain why verifier keys have no pad bits")
	}
	coverage, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	const path = "trust-bad/44-log-key-base64-cr"
	if !strings.Contains(coverage.Body, path) {
		t.Errorf("§12.1 does not cite %s", path)
	}
	if strings.Contains(coverage.Body, "Canonical base64 pad bits in policy verifier keys") {
		t.Error("§12.1 still claims a 33-byte verifier key has unused pad bits")
	}
	var manifest struct {
		Cases []string `json:"cases"`
		Rules map[string]struct {
			Section string `json:"section"`
			Says    string `json:"says"`
		} `json:"rules"`
	}
	readJSON(t, filepath.Join(vectorRoot(t), "trust-bad", "cases.json"), &manifest)
	const name = "44-log-key-base64-cr"
	found := false
	for _, candidate := range manifest.Cases {
		found = found || candidate == name
	}
	if !found {
		t.Errorf("trust-bad/cases.json does not name %s", name)
	}
	rule := manifest.Rules[name]
	if rule.Section != "9.1" || rule.Says != "verifier-key data MUST be canonical RFC 4648 base64" {
		t.Errorf("%s names rule %+v, want §9.1's canonical verifier-key data", name, rule)
	}
}

func TestReceiptLeafHashCanonicalBase64IsNormativeAndVectored(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("7")
	if !ok {
		t.Fatal("§7 is missing")
	}
	const rule = "unused pad bits in the leaf hash MUST be zero"
	if !strings.Contains(section.Body, rule) ||
		!strings.Contains(section.Body, "decoding then re-encoding MUST reproduce the exact line") {
		t.Error("§7 does not require canonical receipt leaf-hash base64")
	}
	coverage, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	const name = "leaf-hash-nonzero-pad-bits.note"
	if !strings.Contains(coverage.Body, "receipt-bad/"+name) {
		t.Errorf("§12.1 does not cite receipt-bad/%s", name)
	}
	var manifest struct {
		Codes map[string]string `json:"codes"`
		Rules map[string]struct {
			Section string `json:"section"`
			Says    string `json:"says"`
		} `json:"rules"`
	}
	readJSON(t, filepath.Join(vectorRoot(t), "receipt-bad", "cases.json"), &manifest)
	if manifest.Codes[name] != "leaf-hash" || manifest.Rules[name].Section != "7" ||
		manifest.Rules[name].Says != rule {
		t.Errorf("%s does not name §7's leaf-hash canonicality rule", name)
	}
}

func TestCheckpointAcquisitionIsSelfContainedAndSourceNeutral(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("15")
	if !ok {
		t.Fatal("§15 is missing")
	}
	for _, phrase := range []string{
		"Checkpoint source does not change trust",
		"MUST pass the same §10 verifier",
		"MUST NOT store a candidate checkpoint",
		"compare the two branches before applying the rollback rule",
		"fork-on-a-shorter-branch",
		"refuse-shrunk",
		"detect/cases.json",
	} {
		if !strings.Contains(section.Body, phrase) {
			t.Errorf("§15 does not state the acquisition rule %q", phrase)
		}
	}
	coverage, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	if !strings.Contains(coverage.Body, "Source-neutral checkpoint acquisition") ||
		!strings.Contains(coverage.Body, "cannot be demonstrated by static vectors alone") {
		t.Error("§12.1 claims no limit for source-neutral acquisition coverage")
	}
}

func TestWitnessClockAndPeerGossipAreSelfContained(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("15")
	if !ok {
		t.Fatal("§15 is missing")
	}
	for _, phrase := range []string{
		"newest quorum time",
		"monotonic elapsed",
		"quorum none",
		"CLOCK_SKEW",
		"direct log fetch",
		"5 minutes",
		"T_g = 30 seconds",
		"r = 3 random proven peers",
		"even when the direct log is healthy",
		"GET /norn/checkpoint",
		"GET /norn/tile/",
		"GET /norn/evidence",
		"WireGuard interface address",
		"independently of checkpoint polling",
	} {
		if !strings.Contains(section.Body, phrase) {
			t.Errorf("§15 does not state witness-time or gossip rule %q", phrase)
		}
	}
	coverage, ok := doc.Section("12.1")
	if !ok || !strings.Contains(coverage.Body, "polling cadence and endpoint access") {
		t.Error("§12.1 does not state the limits of static gossip vectors")
	}
}

func TestEnforcementContractIsSelfContained(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("13")
	if !ok {
		t.Fatal("§13 is missing")
	}
	body := section.Body
	for _, number := range []string{"13.1", "13.2", "13.3"} {
		part, ok := doc.Section(number)
		if !ok {
			t.Fatalf("§%s is missing", number)
		}
		body += part.Body
	}
	// Flattened, because prose wraps: a forbidden phrase split across a line
	// break is still forbidden, and a raw Contains misses it there.
	body = strings.Join(strings.Fields(body), " ")
	for _, phrase := range []string{
		"proven.json", "age_seconds", "written_at_local_clock",
		"observe", "owner", "watchdog", "UNPROVEN_PEER",
		"MISSING_PEER", "EVICTED_PEER", "ReplacePeers",
		"UpdateOnly", "CONTROL_PLANE_FIGHT", "quarantine",
		"missing or invalid trust file", "last verified set",
	} {
		if !strings.Contains(body, phrase) {
			t.Errorf("§13 omits enforcement rule %q", phrase)
		}
	}
	if strings.Contains(body, "normative in `ENFORCEMENT.md`") ||
		strings.Contains(body, "schema in `ENFORCEMENT.md`") {
		t.Error("§13 still delegates its normative contract to ENFORCEMENT.md")
	}
	bundles, ok := doc.Section("8.1")
	if !ok || !strings.Contains(bundles.Body, "degraded retains the last verified set") {
		t.Error("§8.1 still conflates stale views with unproven identities")
	}
	coverage, ok := doc.Section("12.1")
	if !ok || !strings.Contains(coverage.Body, "interface reconciliation and `proven.json` publication cannot be") {
		t.Error("§12.1 does not state the limits of static enforcement vectors")
	}
}

func TestKeyHandlingAndEnrollmentBootstrapAreSelfContained(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("16.3")
	if !ok {
		t.Fatal("§16.3 is missing")
	}
	// Flattened, because prose wraps: a forbidden phrase split across a line
	// break is still forbidden, and a raw Contains misses it there.
	body := strings.Join(strings.Fields(section.Body), " ")
	for _, phrase := range []string{
		"ssh-agent protocol",
		"SSH_AUTH_SOCK",
		"Ed25519",
		"verify every signature the agent returns",
		"skipped, not refused",
		"unencrypted",
		"readable by other users",
		"ssh-add",
		"root ceremony",
		"not normative",
		"MUST NOT rewrite",
		"`--yes` MUST NOT exist for the root role",
		"informative",
	} {
		if !strings.Contains(body, phrase) {
			t.Errorf("§16.3 omits key-handling rule %q", phrase)
		}
	}
	if strings.Contains(body, "normative in `ENROLLMENT.md`") {
		t.Error("§16.3 still delegates its normative contract to ENROLLMENT.md")
	}
	intro, ok := doc.Section("16")
	if !ok {
		t.Fatal("§16 is missing")
	}
	if strings.Contains(intro.Body, "ENROLLMENT.md") {
		t.Error("§16's introduction still cites ENROLLMENT.md")
	}
	rotation, ok := doc.Section("9.4")
	if !ok {
		t.Fatal("§9.4 is missing")
	}
	if !strings.Contains(rotation.Body, "never retired") {
		t.Error("§9.4 does not state that a learned log key is never retired")
	}
	bodies, ok := doc.Section("4.3")
	if !ok {
		t.Fatal("§4.3 is missing")
	}
	if strings.Contains(bodies.Body, "`ENROLLMENT.md`") {
		t.Error("§4.3 still cites ENROLLMENT.md for rotation or device-flow rules")
	}
	requests, ok := doc.Section("16.1")
	if !ok {
		t.Fatal("§16.1 is missing")
	}
	if !strings.Contains(requests.Body, "what you sign is what you see") {
		t.Error("§16.1 does not own the what-you-sign-is-what-you-see rule")
	}
	if strings.Contains(requests.Body, "ENROLLMENT.md") {
		t.Error("§16.1 still cites ENROLLMENT.md for its display rule")
	}
	coverage, ok := doc.Section("12.1")
	if !ok || !strings.Contains(coverage.Body, "key handling cannot be demonstrated") {
		t.Error("§12.1 does not state the limits of static key-handling vectors")
	}
}

// D-064 made the companions informative and the SPEC self-sufficient, and the
// row that closed it (d-xii-v) guards the whole document rather than one
// section: delegation hides anywhere, and the last live one was a bare
// parenthetical on the tail of a §6 sentence about serving tiles onward —
// pointing at `GOSSIP.md` where §15 could be cited instead. The forbidden
// phrases below are the ways a rule quietly moves out of the spec —
// "normative in", "defined in", "per", "see" — flattened with the same
// Fields join the section guards use, because prose wraps and a phrase split
// across a line break is still a phrase.
func TestTheSpecReadingNeedsNoCompanion(t *testing.T) {
	flat := strings.Join(strings.Fields(specText(t)), " ")
	for _, forbidden := range []string{
		"normative in `GOSSIP.md`",
		"normative in `ENFORCEMENT.md`",
		"normative in `ENROLLMENT.md`",
		"defined in `GOSSIP.md`",
		"defined in `ENFORCEMENT.md`",
		"defined in `ENROLLMENT.md`",
		"per `GOSSIP.md`",
		"per `ENFORCEMENT.md`",
		"per `ENROLLMENT.md`",
		"see `GOSSIP.md`",
		"see `ENFORCEMENT.md`",
		"see `ENROLLMENT.md`",
	} {
		if strings.Contains(flat, forbidden) {
			t.Errorf("SPEC.md still delegates a rule to a companion: %q", forbidden)
		}
	}
	for _, required := range []string{
		"The companion documents — `GOSSIP.md`, `ENFORCEMENT.md` and `ENROLLMENT.md` — are **informative**",
		"no rule lives in them (D-064)",
		"onward to its peers (§15)",
	} {
		if !strings.Contains(flat, required) {
			t.Errorf("SPEC.md does not say where its companions stand: %q", required)
		}
	}
}

func TestTheUnseparableBlankLineInsideNoteTextIsAdmitted(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	for _, c := range []struct{ needle, why string }{
		{"blank line inside a note's text",
			"every note text in Norn has a fixed line count, so an embedded blank " +
				"line is refused by the count as well and no file separates the " +
				"first-blank reading from the last"},
	} {
		if !strings.Contains(section.Body, c.needle) {
			t.Errorf("§12.1's `What is not vectored` list does not mention %q — %s",
				c.needle, c.why)
		}
	}
}

// --- Cold-model gate run 10, defect D16 ---------------------------------

func TestTheWitnessMatchRuleNamesBothHalves(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("10")
	if !ok {
		t.Fatal("§10 is missing")
	}
	// §10 settled this for the *log* key — "every signature line whose name
	// and key id match a trusted log key" — and left the witness half saying
	// only "naming". §7 makes the key id bind the name and the algorithm, so
	// the two readings of "naming" are a real fork: ignore a line under a
	// borrowed name, or refuse the checkpoint over it.
	if !strings.Contains(section.Body, "**name and key id**") {
		t.Error("§10 does not say a cosignature line names a listed witness when " +
			"both its name and its key id match — so a line carrying a listed " +
			"name under a stranger's key is a reader's to guess, and the guess " +
			"that refuses lets anyone deny a head to the whole network")
	}
}

// --- Cold-model gate run 10, defect D12 ---------------------------------
//
// Normative rules no artifact can reach. Each was confirmed by deleting it and
// watching all 236 checks stay green — which is not a reason to delete the
// rule, but is a reason to stop counting it as covered. §12.1's standard is
// that a suite admitting its holes is worth more than one that looks complete.

func TestTheDeadNormativeRulesAreAdmitted(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	for _, c := range []struct{ needle, why string }{
		{"a key contributes at most once",
			"`sigs` is sorted by `kid` with no repeats and `kid` is a hash of the " +
				"key, so one key cannot appear twice in one entry and the " +
				"de-duplication never fires"},
		{"in the moment before that refusal",
			"§10 refuses the checkpoint over an unverified line unconditionally, so " +
				"no `T` is ever produced from one and the clause guards a moment " +
				"a conforming reader does not have"},
		{"order of entry 0's steps",
			"every entry-0 failure is `bad-genesis`, so unlike §5.2's ordering this " +
				"one changes no reason code and no file can see it"},
	} {
		if !strings.Contains(section.Body, c.needle) {
			t.Errorf("§12.1's `What is not vectored` list does not mention %q — %s",
				c.needle, c.why)
		}
	}
}

// §5.1 says entry 0's steps are "in order" and gives §5.2's justification for
// saying so — the first matching step decides the reason code. Entry 0 has one
// reason code, so that justification does not apply to it, and a reader who
// takes the phrase at face value believes the suite pins something it cannot.
func TestEntryZerosStepsDoNotClaimAnObservableOrder(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("5.1")
	if !ok {
		t.Fatal("§5.1 is missing")
	}
	if !strings.Contains(section.Body, "every failure here is `bad-genesis`") {
		t.Error("§5.1 presents entry 0's steps as ordered without saying that the " +
			"order carries nothing: every one of them aborts with the same reason " +
			"code, so no artifact distinguishes one arrangement from another")
	}
}

// --- Cold-model gate run 11: the structural note, D11 and D13 -----------
//
// Run 11's largest finding is not a defect in a rule but a hole in what the
// document hands over. §6 defers the `tlog-tiles` layout and does not restate
// it, and that C2SP document is not in the sealed copy — so a reader holding
// only `SPEC.md` and `vectors/` **cannot use `served/`, `served-bad/`,
// `served-*/` or `detect/` at all**. §7 and §9.1 both took the opposite
// decision in as many words: "a verifier cannot be written without it".

func TestTheTilePathsAreRestatedAndTheirExamplesResolve(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("6")
	if !ok {
		t.Fatal("§6 is missing")
	}
	for _, needle := range []string{
		"tile/<L>/",
		"tile/entries/",
		".p/<W>",
	} {
		if !strings.Contains(section.Body, needle) {
			t.Errorf("§6 does not give %q, so a reader with this document and the "+
				"vectors cannot fetch a single tile and every served directory in "+
				"the suite is unusable to them", needle)
		}
	}

	// Worked examples earn their place by resolving: every concrete tile path
	// §6 writes down must be a file the fixture actually serves. A path that
	// went stale when the log grew would teach a reader the wrong shape.
	served := filepath.Join(vectorRoot(t), "served")
	paths := regexp.MustCompile(`tile/(?:entries|[0-9]+)/[0-9./p]+[0-9]`).
		FindAllString(section.Body, -1)
	var concrete int
	for _, path := range paths {
		if strings.ContainsAny(path, "<") {
			continue
		}
		if _, err := os.Stat(filepath.Join(served, filepath.FromSlash(path))); err != nil {
			t.Errorf("§6 gives %q as an example and `served/` has no such file: %v",
				path, err)
			continue
		}
		concrete++
	}
	if concrete < 2 {
		t.Errorf("§6 gives %d resolvable tile paths; it needs one hash tile and one "+
			"entry bundle, or the form is stated and never shown", concrete)
	}
}

// D11. §6 says "a checkpoint body is exactly three lines" and then, four
// bullets later, that an anchor stamps "the checkpoint **body** — the note
// text up to and including the blank line". Those are two byte ranges one
// `0x0A` apart, and §7 uses the *other* one for the signed text. Anchoring is
// advisory, so a reader who computes the three-line digest never matches a
// stamp and never says so: silent divergence, in the one mechanism whose job
// is to constrain the log operator about time.
func TestTheAnchorDigestSaysWhichBytesNotWhichWord(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("6")
	if !ok {
		t.Fatal("§6 is missing")
	}
	for _, needle := range []string{
		"plus the blank line",
		"four `0x0A`",
	} {
		if !strings.Contains(section.Body, needle) {
			t.Errorf("§6's anchor bullet does not say %q — it leans on the word "+
				"\"body\", which §6 itself defined three bullets earlier as the "+
				"three lines *without* the blank separator", needle)
		}
	}
}

// D13. §4.0 opens by naming three artifacts and governs five; the full list is
// two paragraphs further down, which is two paragraphs after a reader has
// scoped their decoder.
func TestTheEncodingProfileNamesEveryArtifactItGoverns(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("4.0")
	if !ok {
		t.Fatal("§4.0 is missing")
	}
	opening := section.Body
	if at := strings.Index(opening, "\n\n"); at > 0 {
		opening = opening[:at]
	}
	for _, needle := range []string{"proof bundle", "fork evidence"} {
		if !strings.Contains(opening, needle) {
			t.Errorf("§4.0's opening sentence does not name %q, so a reader scopes "+
				"their decoder to three artifacts and has to come back for two more",
				needle)
		}
	}
}

// --- Cold-model gate run 11, defect D14 ---------------------------------
//
// §8.1's condition 3 says replay must yield the device "active with that
// `wg_pk`" and never says whose. The nearest antecedent is the bundle's,
// because the whole list is about a bundle — and that reading drops every
// device that has ever rotated, quietly, while passing every check in the
// suite.

func TestConditionThreeSaysWhichKeyItMeans(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("8.1")
	if !ok {
		t.Fatal("§8.1 is missing")
	}
	for _, c := range []struct{ needle, why string }{
		{"the `wg_pk` replay gives",
			"condition 3's `that wg_pk` has no antecedent in its own sentence"},
		{"what the bundle's own entry proves",
			"a reader needs to be told that the bundle proves enrolment at an " +
				"index, not the device's current key — `rotate` leaves " +
				"`since_index` on the enrol, so a stale bundle is the normal " +
				"case for any device that has ever rotated"},
	} {
		if !strings.Contains(section.Body, c.needle) {
			t.Errorf("§8.1 does not say %q — %s", c.needle, c.why)
		}
	}
}

// --- Cold-model gate run 11, defect D1 (D-060) --------------------------

func TestTheFreshnessStatesAreTestedInAStatedOrder(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("8.1")
	if !ok {
		t.Fatal("§8.1 is missing")
	}
	// A table of four predicates two of which can both hold is not a ladder
	// until something says which is consulted first.
	if !strings.Contains(section.Body, "tested in the order given") {
		t.Error("§8.1 presents four states as a table and never says they are " +
			"ordered — but `fresh` and `hard_stale` are both true whenever " +
			"`S_hard < elapsed ≤ S`, so two conforming nodes enforce opposite " +
			"things from the same inputs")
	}
	// And the order has to be the one D-060 chose, stated where the reader is.
	if !strings.Contains(section.Body, "`hard_stale` is tested before `fresh`") {
		t.Error("§8.1 does not say that `hard_stale` is tested before `fresh`, " +
			"which is what makes S_hard a limit the network cannot raise")
	}
}

// --- Cold-model gate run 11, defects D2, D5 and D12 ---------------------

func TestThePolicyGrammarStatesTheRulesItArguesFrom(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("9.1")
	if !ok {
		t.Fatal("§9.1 is missing")
	}
	// The `log lines` row used to argue from two rules the table never stated.
	// Reconciled with a parallel session: key uniqueness is a rule, the log
	// COUNT is not -- upstream allows several `log` lines with distinct keys,
	// and §9.1 promises not to redefine that grammar.
	for _, c := range []struct{ needle, why string }{
		{"a verifier key appears **once** in a policy",
			"the `log lines` row leans on key uniqueness; the reference parser did " +
				"not enforce it, so one key under two names parsed there and was an " +
				"error in Go"},
		{"**more than one is allowed**",
			"`c2sp.org/tlog-policy` rules out only log lines with the SAME key. An " +
				"at-most-one rule shipped briefly here (6.5l-iii) and redefined the " +
				"grammar §9.1 says it restates verbatim"},
		{"**That set is closed**",
			"§9.1 named `\\r`, `\\v`, `\\f` after an em dash, which reads as " +
				"examples; the reference used Unicode `isspace` and refused a " +
				"non-breaking space that Go accepted"},
	} {
		if !strings.Contains(section.Body, c.needle) {
			t.Errorf("§9.1 does not say %q — %s", c.needle, c.why)
		}
	}
	// And the rule that was wrong must not come back.
	if strings.Contains(section.Body, "at most one `log` line") {
		t.Error("§9.1 again limits the grammar to at most one `log` line; that " +
			"limit belongs to the trust file's correspondence rule, not the grammar")
	}
}

// D5. `bad-empty-group` is `group g all` — three fields — so the field-count
// row refuses it before the members row is reached. Both readings refuse, so
// there is no hazard; the fault is that §12.1 credits it to the members rule.
func TestTheEmptyGroupCaseIsCreditedToTheRuleThatRefusesIt(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	if !strings.Contains(section.Body, "refused by the **field count**") {
		t.Error("§12.1 lists `bad-empty-group` under the restated grammar as if it " +
			"exercised the `group` members rule. It does not: the line has three " +
			"fields, so the field-count row fires first and the members rule is " +
			"subsumed")
	}
}

// The vectors README states a count for two directories in words or digits,
// and it has silently drifted twice while cases were added. A number in prose
// that nothing checks is a claim, and §12.1 opens by saying an inaccurate
// coverage claim is the same failure wearing a different hat.
func TestTheVectorsREADMEStatesTheRightCounts(t *testing.T) {
	root := vectorRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	words := map[int]string{
		1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
		7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven",
		12: "twelve", 13: "thirteen", 14: "fourteen", 15: "fifteen",
		16: "sixteen", 17: "seventeen", 18: "eighteen", 19: "nineteen",
		20: "twenty", 21: "twenty-one", 22: "twenty-two", 23: "twenty-three",
		24: "twenty-four", 25: "twenty-five", 26: "twenty-six", 27: "twenty-seven",
		28: "twenty-eight", 29: "twenty-nine", 30: "thirty",
	}
	for _, c := range []struct{ dir, noun string }{
		{"checkpoints-bad", "checkpoints that MUST be refused"},
		{"trust-bad", "anchors that must be rejected"},
		// 6.5l-vii-b-ii: fork/ said "twelve", in an old step numbering, and
		// named seven of them; nothing checked it.
		{"proofs-bad", "bundles that MUST be refused"},
		{"fork", "that must be **refused**"},
	} {
		n := len(caseNames(t, root, c.dir))
		row := readmeRow(t, string(raw), "`"+c.dir+"/`")
		digits := fmt.Sprintf("%d %s", n, c.noun)
		// Only a number the table can spell is matched spelled. This used
		// words[n] unconditionally, and past twenty-five that is "", so the
		// "spelled" form was the bare noun -- contained in any row that ends
		// in it, whatever its number. `trust-bad/` has had more than
		// twenty-five cases since the guard was written and was never checked
		// (6.5l-vii-d-iv-b).
		word, spellable := words[n]
		spelled := word + " " + c.noun
		if !strings.Contains(row, digits) && (!spellable || !strings.Contains(row, spelled)) {
			t.Errorf("`%s/` ships %d cases and its README row says neither %q nor %q",
				c.dir, n, digits, spelled)
		}
	}
}

// --- Cold-model gate run 11, defect D6 ----------------------------------
//
// §4.0 counts `name`, `reason`, `text` and label values in **bytes**. The
// prose is unambiguous; the vectors were not. Every over-long negative was
// pure ASCII and exactly one byte past its cap, so bytes and characters gave
// the same answer and `TextCapChars` and `LabelValueChars` — readers that
// count runes — passed all 622 checks.
//
// §12.1 records finding and fixing precisely this for §4.0's map-key cap in
// run 9 ("both were ASCII until run 9, so 23 bytes and 23 characters gave the
// same answer everywhere"). The same fix was not carried to the four field
// caps.
//
// `reason` is the clearest: free-form human text on a `revoke`, where 256
// bytes is about 85 CJK characters. A revocation written in any non-Latin
// script and run past the cap is `decode` for one reader and accepted by the
// other, so the two disagree about whether the device is revoked at all —
// and §5.3 makes `state.json` a byte-identical MUST.

func TestTheByteCapsAreSeparatedFromCharacterCounting(t *testing.T) {
	root := vectorRoot(t)
	for _, c := range []struct {
		what string
		cap  int
		text string
	}{
		{"revoke `reason`", 256, logEntryField(t, root, "-bad-revoke-reason-too-long", "reason")},
		{"note `text`", 4096, logEntryField(t, root, "-bad-text-too-long", "text")},
		{"genesis `name`", 64, genesisName(t, root, "14-name-too-long")},
	} {
		t.Run(c.what, func(t *testing.T) {
			bytes := len(c.text)
			runes := len([]rune(c.text))
			if bytes <= c.cap {
				t.Fatalf("%d bytes is not over the %d-byte cap", bytes, c.cap)
			}
			if runes > c.cap {
				t.Errorf("%s is %d bytes and %d characters, and the cap is %d — over "+
					"it both ways, so a reader counting characters refuses it too and "+
					"nothing separates the two readings. It needs multi-byte content: "+
					"over the cap in bytes and under it in characters",
					c.what, bytes, runes, c.cap)
			}
		})
	}
}

// logEntryField pulls one body field from the log entry whose name ends in
// suffix, as a string.
func logEntryField(t *testing.T, root, suffix, field string) string {
	t.Helper()
	var doc struct {
		Entries []struct{ Name string } `json:"entries"`
	}
	readJSON(t, filepath.Join(root, "log", "manifest.json"), &doc)
	for _, e := range doc.Entries {
		if !strings.HasSuffix(e.Name, suffix) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, "log", e.Name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		env, err := entrypkg.Decode(raw)
		if err != nil {
			// The entry is deliberately malformed for its own rule; read the
			// field out of the raw map instead.
			value, err := cborpkg.Decode(raw)
			if err != nil {
				t.Fatalf("%s does not decode at all: %v", e.Name, err)
			}
			m, _ := value.(map[string]any)
			body, _ := m["body"].(map[string]any)
			s, _ := body[field].(string)
			return s
		}
		s, _ := env.Body[field].(string)
		return s
	}
	t.Fatalf("no log entry named *%s", suffix)
	return ""
}

func genesisName(t *testing.T, root, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "genesis", dir, "00-genesis.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := cborpkg.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := value.(map[string]any)
	body, _ := m["body"].(map[string]any)
	s, _ := body["name"].(string)
	return s
}

// --- Cold-model gate run 11, defect D10 ---------------------------------
//
// §5.2 is a closed, normative list of sixteen reason codes — for replay, and
// for nothing else. The trust file, the policy parser, the note and checkpoint
// parsers, the bundle and evidence checkers, the request decoder and the CBOR
// profile all refuse without one. The vectors nevertheless score against
// strings: `entries-hostile`'s `says` reads `simple value`, `deeper than`,
// `map key must be 1-23 bytes`; `fork`'s reads `can only speak for what it
// holds`. None of those phrases is in this document.
//
// Run 11 reverse-engineered its error vocabulary from `cases.json` to make the
// suite pass — so for those checks the suite measured its ability to read
// `cases.json`, not the specification. §12 has to say what `says` is, or the
// next reader does the same.

func TestTheSuiteSaysWhatItsSaysFieldIs(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12")
	if !ok {
		t.Fatal("§12 is missing")
	}
	for _, c := range []struct{ needle, why string }{
		{"`says` is a **semantic hint**",
			"a reader who takes it for a required string reverse-engineers an " +
				"error vocabulary out of a JSON file instead of reading this document"},
		{"not the bytes your implementation must produce",
			"the suite asks that a negative be refused for the right reason, not " +
				"that two implementations phrase it the same way"},
	} {
		if !strings.Contains(section.Body, c.needle) {
			t.Errorf("§12 does not say %q — %s", c.needle, c.why)
		}
	}
}

// §12.1 once had to admit orderings pinned only by a `says` match, because
// outside replay two refusals were the same event to a black-box run. D-061
// gave the verifier and the evidence reader closed codes, and the codes make
// an ordering *observable*; run 12 (D5) answered that observable is not
// observed -- head-before-fork had a code on each side and no file with both
// faults. So the admission is gone, and §12.1 names, for every ordering
// §10.1 and §11.1 state, the file that fails both steps (6.5l-vii-d-ii).
func TestEveryStatedOrderingIsObservedByAVector(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	flat := strings.Join(strings.Fields(section.Body), " ")
	if strings.Contains(flat, "pinned only by a `says` match") {
		t.Error("§12.1 still admits an ordering pinned only by a `says` match; every " +
			"stated ordering has a coded vector")
	}
	for _, vector := range []string{
		"checkpoints-bad/01-unsigned", "checkpoints-bad/03-wrong-origin",
		"served-bad/tampered-entry-bundle", "detect/tampered-bundle-under-a-stored-head",
		"proofs-bad/foreign-checkpoint", "proofs-bad/no-quorum-tampered-proof",
		"proofs-bad/wrong-entry", "fork/bad-oversize-and-not-cbor",
		"fork/bad-version-and-unknown-key", "fork/bad-short-held-root-and-size-above-held",
		"fork/bad-other-origin", "fork/bad-policy-unparseable-and-foreign-held",
	} {
		if !strings.Contains(flat, vector) {
			t.Errorf("§12.1 does not name %s, a vector that observes one of the orderings "+
				"§10.1 or §11.1 states", vector)
		}
		if _, err := os.Stat(filepath.Join(vectorRoot(t), filepath.Dir(vector))); err != nil {
			t.Errorf("%s: %v", vector, err)
		}
	}
}

// The guard above checks that §8.1 *says* `hard_stale` is tested first. It
// passed while the table beneath said the opposite: 6.5l-ii-b wrote "the
// states are tested in the order given" and "`hard_stale` is tested before
// `fresh`" and left the table listing `fresh` first, so the section
// contradicted itself and every phrase check was green. Reconciling a
// parallel session's work surfaced it. A rule about an order is checked
// against the order.
func TestTheFreshnessTableIsInTheOrderItIsEvaluated(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("8.1")
	if !ok {
		t.Fatal("§8.1 is missing")
	}
	var order []string
	for _, line := range strings.Split(section.Body, "\n") {
		for _, state := range []string{"unknown", "hard_stale", "fresh", "degraded"} {
			if strings.HasPrefix(line, "| `"+state+"` |") {
				order = append(order, state)
			}
		}
	}
	want := []string{"unknown", "hard_stale", "fresh", "degraded"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("§8.1's freshness table lists %v; D-060 evaluates it top to bottom "+
			"as %v. A table read in order and a sentence saying otherwise is a "+
			"section that contradicts itself", order, want)
	}
}

// D-060 is checked in SPEC.md and GOSSIP.md; the vectors README restates the
// same table for whoever starts from the vectors, and nothing checked it. Its
// `detect/` row kept the remote session's "`fresh` wins" through the 6.5l-ii
// reconciliation, and cold gate run 12 read it (D21a): a second implementer
// who trusts the README implements the order the specification rejects.
func TestTheVectorsREADMEStatesD060(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(t), "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	row := strings.Join(strings.Fields(readmeRow(t, string(raw), "`detect/`")), " ")
	if strings.Contains(row, "`fresh` wins") {
		t.Error("the vectors README's detect/ row says `fresh` wins; D-060 says `hard_stale`")
	}
	if !strings.Contains(row, "`hard_stale` wins") {
		t.Error("the vectors README's detect/ row does not say `hard_stale` wins where both hold")
	}
}

// --- D-061: closed refusal codes for §10 --------------------------------
//
// §5.2 gives replay a closed vocabulary, and that is the only reason §5.1's
// step order can be vectored: two refusals are distinguishable. Outside replay
// every refusal was the same event to a black-box run, so §10's
// signature-before-origin and §11.1's step orderings were pinned only by a
// `says` phrase (cold gate run 11, D10). D-061 gives the verifier the same
// kind of list. This is the specification half; the implementation and the
// vectors that make each ordering observable come next (6.5l-vi-b-ii).

// verifierCodes is the vocabulary D-061 asks for, in the order §10.1 must
// give it: the verifier loop's thirteen, then the bundle check's three. It is
// read from `internal/refusal` rather than spelled out again here, so the
// code has one list and these tests hold the document to it.
var verifierCodes = func() []string {
	var out []string
	for _, c := range refusal.All() {
		out = append(out, string(c))
	}
	return out
}()

// The package and the table are one list: the same sixteen codes, in the same
// order, the loop's table first and the bundle's second. The test above checks
// the loop's precedence; this one also pins where the bundle's three sit, so a
// reorder on either side -- a code moved in the package, a row moved in the
// document -- is a failure here and not a quiet disagreement between a
// verifier and the specification it cites.
func TestTheRefusalPackageIsSection10_1(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("10.1")
	if !ok {
		t.Fatal("§10.1 is missing")
	}
	var table []string
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| *[0-9]+ *\\| *`([a-z-]+)` *\\|").FindAllStringSubmatch(section.Body, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			table = append(table, m[1])
		}
	}
	if got, want := strings.Join(table, " "), strings.Join(verifierCodes, " "); got != want {
		t.Errorf("§10.1's tables list\n  %s\nand internal/refusal lists\n  %s", got, want)
	}
}

func TestTheVerifierHasAClosedListOfRefusalCodes(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("10.1")
	if !ok {
		t.Fatal("§10.1 is missing: D-061 gives the verifier a closed list of refusal " +
			"codes in §5.2's style, and there is nowhere that says what they are")
	}
	if !strings.Contains(section.Body, "closed list") {
		t.Error("§10.1 does not say its list is closed. An open list is a vocabulary " +
			"two implementations extend differently")
	}

	// Every code is in the table, once, in the stated order.
	var order []string
	seen := map[string]int{}
	for _, line := range strings.Split(section.Body, "\n") {
		m := regexp.MustCompile("^\\| *[0-9]+ *\\| *`([a-z-]+)` *\\|").FindStringSubmatch(line)
		if m == nil {
			continue
		}
		seen[m[1]]++
		if seen[m[1]] == 1 {
			order = append(order, m[1])
		}
	}
	for _, code := range verifierCodes {
		if seen[code] == 0 {
			t.Errorf("§10.1 does not define `%s`", code)
		}
	}
	for code := range seen {
		var known bool
		for _, c := range verifierCodes {
			known = known || c == code
		}
		if !known {
			t.Errorf("§10.1 defines `%s`, which D-061's list does not have", code)
		}
	}

	// The loop's codes appear in precedence order. `unserved` recurs at every
	// step that fetches a file, so it is placed by its first use.
	loop := verifierCodes[:13]
	var got []string
	for _, c := range order {
		for _, l := range loop {
			if c == l {
				got = append(got, c)
			}
		}
	}
	if strings.Join(got, ",") != strings.Join(loop, ",") {
		t.Errorf("§10.1 lists the loop's codes as %v; the precedence is %v", got, loop)
	}
}

// --- D-061: closed refusal codes for §11 -------------------------------
//
// The evidence reader gets the same treatment: a closed list in `internal/evrefusal`
// and a matching table in SPEC.md §11.1, so the package and the document cannot drift.

var evidenceCodes = func() []string {
	var out []string
	for _, c := range evrefusal.All() {
		out = append(out, string(c))
	}
	return out
}()

func TestTheEvidenceRefusalPackageIsSection11_1(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("11.1")
	if !ok {
		t.Fatal("§11.1 is missing")
	}
	var table []string
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| *[0-9]+ *\\| *`([a-z-]+)` *\\|").
		FindAllStringSubmatch(section.Body, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			table = append(table, m[1])
		}
	}
	if got, want := strings.Join(table, " "), strings.Join(evidenceCodes, " "); got != want {
		t.Errorf("§11.1's table lists\n  %s\nand internal/evrefusal lists\n  %s", got, want)
	}
}

func TestTheEvidenceReaderHasAClosedListOfRefusalCodes(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("11.1")
	if !ok {
		t.Fatal("§11.1 is missing")
	}
	if !strings.Contains(section.Body, "closed list") {
		t.Error("§11.1 does not say its refusal list is closed")
	}
	var order []string
	seen := map[string]int{}
	for _, line := range strings.Split(section.Body, "\n") {
		m := regexp.MustCompile("^\\| *[0-9]+ *\\| *`([a-z-]+)` *\\|").
			FindStringSubmatch(line)
		if m == nil {
			continue
		}
		seen[m[1]]++
		if seen[m[1]] == 1 {
			order = append(order, m[1])
		}
	}
	for _, code := range evidenceCodes {
		if seen[code] == 0 {
			t.Errorf("§11.1 does not define `%s`", code)
		}
	}
	for code := range seen {
		var known bool
		for _, c := range evidenceCodes {
			known = known || c == code
		}
		if !known {
			t.Errorf("§11.1 defines `%s`, which internal/evrefusal does not have", code)
		}
	}
	if strings.Join(order, ",") != strings.Join(evidenceCodes, ",") {
		t.Errorf("§11.1 lists the codes as %v; the precedence is %v", order, evidenceCodes)
	}
}

// None of the evidence codes may collide with §10.1's or §5.2's: a code has to
// mean one thing wherever an operator reads it.
func TestTheEvidenceCodesDoNotCollideWithOthers(t *testing.T) {
	doc := load(t)
	for _, sec := range []string{"5.2", "10.1"} {
		section, ok := doc.Section(sec)
		if !ok {
			t.Fatalf("§%s is missing", sec)
		}
		for _, code := range evidenceCodes {
			if strings.Contains(section.Body, "| `"+code+"` |") {
				t.Errorf("`%s` is both an evidence refusal (§11.1) and a §%s code", code, sec)
			}
		}
	}
}

// None of the new §10.1 codes may collide with §5.2's: a reason code has to mean
// one thing wherever an operator reads it.
func TestTheVerifierCodesDoNotCollideWithReplays(t *testing.T) {
	doc := load(t)
	replay, ok := doc.Section("5.2")
	if !ok {
		t.Fatal("§5.2 is missing")
	}
	for _, code := range verifierCodes {
		if strings.Contains(replay.Body, "| `"+code+"` |") {
			t.Errorf("`%s` is both a replay reason code (§5.2) and a verifier refusal "+
				"(§10.1); one word, two meanings", code)
		}
	}
}

// §12.1 admitted that a note with no signature lines was a rule no file could
// isolate, and said the admission would leave once §10.1's codes were
// vectored. They are: 01-unsigned names `note`, and a reader that looks for a
// trusted signature before framing the note answers `log-signature` -- so the
// file isolates the rule, and the admission goes. §7 carried the same
// admission, with the order backwards; that sentence goes too.
func TestTheNoSignatureLinesAdmissionHasLeftTheList(t *testing.T) {
	doc := load(t)
	var manifest struct {
		Codes map[string]string `json:"codes"`
	}
	readJSON(t, filepath.Join(vectorRoot(t), "checkpoints-bad", "cases.json"), &manifest)
	// The admission said it would leave once the separation was a vector, and
	// it is one exactly when 01-unsigned names `note`.
	if manifest.Codes["01-unsigned"] != "note" {
		t.Fatalf("checkpoints-bad/01-unsigned names %q; §10.1 frames the note before "+
			"looking for a signature, so it is `note`", manifest.Codes["01-unsigned"])
	}
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	// Collapse line breaks first: a phrase that spans a wrap in the source
	// passes a plain Contains against the text that says it.
	if flat := strings.Join(strings.Fields(section.Body), " "); strings.Contains(flat,
		"A note with no signature lines") {
		t.Error("§12.1 still lists a note with no signature lines as a rule no file " +
			"isolates; 01-unsigned's code isolates it")
	}
	seven, ok := doc.Section("7")
	if !ok {
		t.Fatal("§7 is missing")
	}
	flat := strings.Join(strings.Fields(seven.Body), " ")
	for _, stale := range []string{"refuses such a checkpoint first",
		"lists this rule as one no file can isolate"} {
		if strings.Contains(flat, stale) {
			t.Errorf("§7 still says %q: §10.1 frames the note first, and 01-unsigned "+
				"is the file that isolates the rule", stale)
		}
	}
}

// A negative's `rules` entry says which rule refuses it, and its code says
// which step does. They have to be the same rule. Before codes nothing could
// compare them, and two cases cited a rule a later step states: 01-unsigned
// cited §10's "verify log signature" and is refused by §7's framing, and
// 03-wrong-origin cited the origin comparison and is refused by the signature
// -- it is signed under another origin's name. A citation that names a step
// the case never reaches tells a reader the wrong rule is under test.
// The same question for the other two manifests that carry codes, where the
// sections do not separate the steps -- §6 states both the head comparison
// and the tile rule, §8.1 every step of a bundle -- so the citation itself is
// held to its code. served-bad/ cited §6's tile sentence for a tampered entry
// bundle, which §10.1 refuses at the head, and for a missing one, which is
// `unserved`; the vectors README said the tile rule caught the tamper cases
// "first", which is the order §10.1 does not have.
// The four manifests whose negatives a verifier refuses with a closed-list
// code all carry it the same way: a `codes` map beside `cases`, one entry per
// case, every code on its list -- §10.1's for the verifier, §11.1's for an
// evidence reader. `says` stays what §12 makes it, a semantic hint, and a hint
// that is only the case's own code name says nothing the code does not.
// fork/ was the exception for a day: its hints were overwritten with code
// names and it carried no `codes` map (6.5l-vii-b-i).
func TestEveryCodedManifestKeepsItsCodesInCodes(t *testing.T) {
	inRefusal := func(c string) bool { return refusal.Known(refusal.Code(c)) }
	inEvidence := func(c string) bool { return evrefusal.Known(evrefusal.Code(c)) }
	for dir, known := range map[string]func(string) bool{
		"checkpoints-bad": inRefusal, "served-bad": inRefusal,
		"proofs-bad": inRefusal, "fork": inEvidence,
		"receipt-bad": func(c string) bool { return receiptpkg.Known(receiptpkg.Code(c)) },
	} {
		t.Run(dir, func(t *testing.T) {
			var manifest struct {
				Cases json.RawMessage   `json:"cases"`
				Codes map[string]string `json:"codes"`
			}
			readJSON(t, filepath.Join(vectorRoot(t), dir, "cases.json"), &manifest)
			// `cases` is bare names in checkpoints-bad and objects elsewhere.
			type entry struct{ Name, Says string }
			var cases []entry
			if err := json.Unmarshal(manifest.Cases, &cases); err != nil {
				// A failed unmarshal leaves the slice holding empties, so the
				// fallback starts from nil (the trap the rules guard notes).
				cases = nil
				var names []string
				if err := json.Unmarshal(manifest.Cases, &names); err != nil {
					t.Fatal(err)
				}
				for _, n := range names {
					cases = append(cases, entry{Name: n})
				}
			}
			if len(manifest.Codes) != len(cases) {
				t.Fatalf("%d cases and %d codes", len(cases), len(manifest.Codes))
			}
			for _, c := range cases {
				code, ok := manifest.Codes[c.Name]
				switch {
				case !ok:
					t.Errorf("%s has no code", c.Name)
				case !known(code):
					t.Errorf("%s names %q, which is not on the closed list", c.Name, code)
				case c.Says != "" && c.Says == code:
					t.Errorf("%s's `says` is its own code name, %q: a hint that only "+
						"repeats the code says nothing the code does not", c.Name, code)
				}
			}
		})
	}
}

func TestReceiptCodesAreDeclaredInCheckOrder(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	spec := string(raw)
	start := strings.Index(spec, "### Checking a receipt")
	if start < 0 {
		t.Fatal("SPEC.md has no complete receipt-checking section")
	}
	end := strings.Index(spec[start:], "\n## 8.")
	if end < 0 {
		t.Fatal("SPEC.md has no complete receipt-checking section")
	}
	section := spec[start : start+end]
	previous := -1
	for _, code := range receiptpkg.All() {
		row := "| `" + string(code) + "` |"
		at := strings.Index(section, row)
		if at < 0 {
			t.Errorf("§7 does not declare receipt code %q", code)
			continue
		}
		if at <= previous {
			t.Errorf("§7 receipt code %q is out of Check order", code)
		}
		previous = at
	}
}

func TestEveryServedAndBundleNegativeCitesTheRuleOfItsCode(t *testing.T) {
	for dir, citeFor := range map[string]map[string][]string{
		"served-bad": {
			"head":     {"that comparison is what binds the entries to the head"},
			"entries":  {"A partial bundle holds **exactly** the number of entries its path declares"},
			"tiles":    {"checking them is not optional"},
			"unserved": {"any file a later step needs and cannot fetch"},
		},
		"proofs-bad": {
			"bundle":        {"a closed map of exactly these six keys", "`v` | uint | `1`", "larger than this MUST be refused on length"},
			"log-signature": {"under the log keys the verifier trusts"},
			"origin":        {"this network's origin"},
			"quorum":        {"a satisfied witness quorum"},
			"inclusion":     {"reach that checkpoint's root at `index`"},
			"binding":       {"`device` is the `device_id` the `entry` names"},
		},
		"receipt-bad": {
			"note":          {"a second `0x0A` after the final signature creates a forbidden blank line"},
			"log-signature": {"The note MUST verify under a log key the verifier trusts"},
			"receipt":       {"The first line MUST be", "Require exactly four signed-text lines"},
			"origin":        {"The origin line MUST equal the anchored origin"},
			"leaf-hash":     {"The leaf hash MUST be standard base64 and decode to exactly 32 bytes", "unused pad bits in the leaf hash MUST be zero"},
			"deadline":      {"The deadline MUST be canonical decimal", "at most 2⁶³−1"},
			"entry":         {"the submitted entry's leaf hash MUST equal the receipt's leaf hash"},
			"expired":       {"A nonzero checking time at or after the deadline MUST refuse the receipt"},
		},
	} {
		t.Run(dir, func(t *testing.T) {
			var manifest struct {
				Codes map[string]string `json:"codes"`
				Rules map[string]struct {
					Says string `json:"says"`
				} `json:"rules"`
			}
			readJSON(t, filepath.Join(vectorRoot(t), dir, "cases.json"), &manifest)
			if len(manifest.Codes) == 0 {
				t.Fatalf("%s/cases.json names no codes", dir)
			}
			for name, code := range manifest.Codes {
				allowed, ok := citeFor[code]
				if !ok {
					t.Errorf("%s is coded %q, which nothing in %s can be refused with", name, code, dir)
					continue
				}
				var cites bool
				for _, phrase := range allowed {
					cites = cites || manifest.Rules[name].Says == phrase
				}
				if !cites {
					t.Errorf("%s is refused as `%s` and cites %q; the rule of that step is %q",
						name, code, manifest.Rules[name].Says, allowed)
				}
			}
		})
	}
}

func TestEveryBadCheckpointCitesTheRuleOfItsCode(t *testing.T) {
	var manifest struct {
		Codes map[string]string `json:"codes"`
		Rules map[string]struct {
			Section string `json:"section"`
			Says    string `json:"says"`
		} `json:"rules"`
	}
	readJSON(t, filepath.Join(vectorRoot(t), "checkpoints-bad", "cases.json"), &manifest)
	if len(manifest.Codes) == 0 {
		t.Fatal("checkpoints-bad/cases.json names no codes")
	}
	// §10.1's steps 2 to 7, by the section that states each one's rule.
	sectionOf := map[string]string{"note": "7", "log-signature": "10", "checkpoint": "6",
		"origin": "10", "cosignature": "10", "quorum": "10"}
	originRule := func(says string) bool {
		return strings.Contains(says, "cp.origin == norn.trust.origin") ||
			strings.Contains(says, "which log this is about")
	}
	for name, code := range manifest.Codes {
		rule, ok := manifest.Rules[name]
		if !ok {
			t.Errorf("%s has a code and no rule", name)
			continue
		}
		want, ok := sectionOf[code]
		if !ok {
			t.Errorf("%s names %q, which no checkpoint can be refused with", name, code)
			continue
		}
		if rule.Section != want {
			t.Errorf("%s is refused as `%s`, whose rule §%s states, and cites §%s",
				name, code, want, rule.Section)
		}
		if originRule(rule.Says) != (code == "origin") {
			t.Errorf("%s is refused as `%s` and cites %q: only an `origin` refusal is "+
				"about the origin comparison", name, code, rule.Says)
		}
	}
}

func TestTheCBORProfileIsAnAllowList(t *testing.T) {
	section, ok := load(t).Section("4.0")
	if !ok {
		t.Fatal("§4.0 is missing")
	}
	flat := strings.Join(strings.Fields(strings.ReplaceAll(section.Body, "*", "")), " ")
	for _, phrase := range []string{"The profile is an allow-list", "every other simple value is forbidden"} {
		if !strings.Contains(flat, phrase) {
			t.Errorf("§4.0 omits %q", phrase)
		}
	}
}
