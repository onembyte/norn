package specdoc

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/proof"
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
	// The sentence names them by their numeric prefix.
	for _, name := range doc.Blind {
		prefix, _, _ := strings.Cut(name, "-")
		if !strings.Contains(string(readme), "`"+prefix+"`") {
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
		if strings.Contains(string(readme), "`"+prefix+"` and") ||
			strings.Contains(string(readme), "and `"+prefix+"`") {
			t.Errorf("the vectors README lists `%s` among the files a signature-blind "+
				"verifier accepts; it does not", prefix)
		}
	}
}
