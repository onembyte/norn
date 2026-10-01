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

	cborpkg "github.com/onembyte/norn/internal/cbor"
	entrypkg "github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/proof"
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
			LogKey: anchor.LogKey, Policy: anchor.Policy}); err != nil {
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
// the claim that those four are the set "and nothing else here".
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
	named := map[string]bool{}
	for _, w := range rules.Witnesses {
		named[w.Name] = true
	}

	// blindly reads a note the way a reader that checks no signature does --
	// and no other way. "Blind" means it never calls Ed25519; it still enforces
	// everything §7's framing decides without a key, so
	// `14-unterminated-signature-block` is refused by such a reader and is not
	// part of this set. Modelling blind as "ignores the note format too" put it
	// in, which would have been a wrong answer arrived at by a computation
	// rather than by a stale list -- no better.
	blindly := func(text string) (body string, who []string) {
		body, block, found := strings.Cut(text, "\n\n")
		if !found || !strings.HasSuffix(block, "\n") {
			return "", nil
		}
		for _, line := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
			rest, ok := strings.CutPrefix(line, "— ")
			if !ok {
				return "", nil // unparseable framing: refused without any signature
			}
			// The payload's encoding and length need no key either, so a
			// blind reader still enforces them: §7 makes the base64 standard
			// and padded and the decoded payload exactly 68 or 76 bytes, and
			// `18`, `19` and `20` break one of those each. Leaving them out
			// of the model would have put three cases in this set that no
			// reader of any kind accepts (cold gate run 10, D13).
			name, blob, ok := strings.Cut(rest, " ")
			if !ok {
				return "", nil
			}
			raw, err := base64.StdEncoding.DecodeString(blob)
			if err != nil || (len(raw) != 68 && len(raw) != 76) {
				return "", nil
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
		"entries-hostile", "policies", "genesis", "trust-bad",
	} {
		t.Run(dir, func(t *testing.T) {
			var manifest struct {
				Cases json.RawMessage `json:"cases"`
				Rules map[string]struct {
					Section string `json:"section"`
					Says    string `json:"says"`
				} `json:"rules"`
			}
			readJSON(t, filepath.Join(root, dir, "cases.json"), &manifest)
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
			if err := json.Unmarshal(manifest.Cases, &names); err != nil {
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
	for _, suffix := range []string{
		"-signature-name-with-space",
		"-signature-unpadded-base64",
		"-signature-payload-too-long",
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
		if rule := manifest.Rules[found]; rule.Section != "7" {
			t.Errorf("%s names §%s; the note framing is §7's", found, rule.Section)
		}
	}
}

func TestTheTwoUnseparableFramingRulesAreAdmitted(t *testing.T) {
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
		{"note with no signature lines",
			"something has to verify, so a note with none is refused by §10's " +
				"requirement before §7's framing is reached"},
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
		24: "twenty-four", 25: "twenty-five",
	}
	for _, c := range []struct{ dir, noun string }{
		{"checkpoints-bad", "checkpoints that MUST be refused"},
		{"trust-bad", "anchors that must be rejected"},
	} {
		n := len(caseNames(t, root, c.dir))
		row := readmeRow(t, string(raw), "`"+c.dir+"/`")
		digits := fmt.Sprintf("%d %s", n, c.noun)
		spelled := words[n] + " " + c.noun
		if !strings.Contains(row, digits) && !strings.Contains(row, spelled) {
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

// ...and the three rules whose only pin is a `says` match have to be named,
// because a semantic hint cannot carry a normative ordering.
func TestTheOrderingsPinnedOnlyByASaysMatchAreNamed(t *testing.T) {
	doc := load(t)
	section, ok := doc.Section("12.1")
	if !ok {
		t.Fatal("§12.1 is missing")
	}
	if !strings.Contains(section.Body, "pinned only by a `says` match") {
		t.Error("§12.1 does not record that §10's signature-before-origin ordering " +
			"and §11.1's two step orderings are observable only through `says`. " +
			"Outside replay there is no reason code, so two refusals are the same " +
			"event to a black-box run — and an ordering between them cannot be " +
			"seen at all")
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
// give it: the verifier loop's twelve, then the bundle check's three. It is
// read from `internal/refusal` rather than spelled out again here, so the
// code has one list and these tests hold the document to it.
var verifierCodes = func() []string {
	var out []string
	for _, c := range refusal.All() {
		out = append(out, string(c))
	}
	return out
}()

// The package and the table are one list: the same fifteen codes, in the same
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
	loop := verifierCodes[:12]
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

// None of the new codes may collide with §5.2's: a reason code has to mean
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
