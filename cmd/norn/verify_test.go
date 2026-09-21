package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The CLI is where a person meets the protocol, so these tests care about what
// it refuses and what it says, not only that it runs.

func nornBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "norn")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building norn: %v\n%s", err, out)
	}
	return bin
}

func vectors() string { return filepath.Join("..", "..", "testdata", "vectors") }

func TestVerifyRefusesWithoutAnAnchor(t *testing.T) {
	out, err := exec.Command(nornBinary(t), "verify", "-log", vectors()+"/served").CombinedOutput()
	if err == nil {
		t.Fatal("verifying without a trust file must fail")
	}
	if !strings.Contains(string(out), "-trust is required") {
		t.Errorf("the error should say what is missing, got:\n%s", out)
	}
}

func TestVerifyRefusesAnUnusableAnchor(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "trust.cbor")
	src, err := os.ReadFile(filepath.Join(vectors(), "trust-bad", "07-no-witnesses.cbor"))
	if err != nil {
		t.Skip("trust-bad vector not present")
	}
	if err := os.WriteFile(bad, src, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(nornBinary(t), "verify", "-trust", bad,
		"-log", filepath.Join(vectors(), "served")).CombinedOutput()
	if err == nil {
		t.Fatal("an anchor that fails validation must be refused")
	}
	if !strings.Contains(string(out), "not a usable anchor") {
		t.Errorf("unexpected error:\n%s", out)
	}
}

func TestVerifyReportsAnUnknownCommandClearly(t *testing.T) {
	out, _ := exec.Command(nornBinary(t), "frobnicate").CombinedOutput()
	if !strings.Contains(string(out), "unknown command") || !strings.Contains(string(out), "verify") {
		t.Errorf("an unknown command should name itself and list the real ones, got:\n%s", out)
	}
}

func TestVerifyRefusesALogThatDoesNotMatchTheAnchor(t *testing.T) {
	// The shipped served log is signed for the fixture network, but the
	// fixture trust file pins the fixture genesis -- so pointing verify at a
	// directory with no log at all must fail rather than report an empty
	// network as if it were healthy.
	empty := t.TempDir()
	out, err := exec.Command(nornBinary(t), "verify",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", empty).CombinedOutput()
	if err == nil {
		t.Fatalf("an unreachable log must fail, got:\n%s", out)
	}
}

// `norn verify --anchored` (D-009, PLAN's Phase 4 gate). Advisory: it reports,
// it never decides, and a network with no anchor is not a network with a
// problem.
func TestVerifyAnchoredReportsTheAnchor(t *testing.T) {
	bin := nornBinary(t)
	log := anchoredLog(t)

	out, stderr, err := run(t, bin, "verify", "-trust",
		filepath.Join(vectors(), "trust.cbor"), "-log", log, "-anchored")
	if err != nil {
		t.Fatalf("verify -anchored: %v\n%s", err, stderr)
	}
	if !strings.Contains(out, "800000") {
		t.Errorf("the block the proof commits into should be reported:\n%s", out)
	}
	// And it must not sound like Norn checked a blockchain.
	if !strings.Contains(out, "not checked here") {
		t.Errorf("the summary must say what was not checked:\n%s", out)
	}
}

// A log with no anchor is reported as such, and verification still succeeds:
// anchoring is advisory, and a node that refused a perfectly good log for
// want of an optional extra would be enforcing the opposite of D-009.
func TestVerifyAnchoredIsAdvisory(t *testing.T) {
	bin := nornBinary(t)

	out, stderr, err := run(t, bin, "verify", "-trust",
		filepath.Join(vectors(), "trust.cbor"),
		"-log", filepath.Join(vectors(), "served"), "-anchored")
	if err != nil {
		t.Fatalf("a log with no anchor must still verify: %v\n%s", err, stderr)
	}
	if !strings.Contains(out, "no anchor") {
		t.Errorf("the absence should be reported:\n%s", out)
	}
}

// An anchor that does not belong to this checkpoint is reported loudly. It is
// still advisory -- it does not change what the log proves -- but a stamp for
// other bytes is exactly the sign of a checkpoint edited after stamping.
func TestVerifyAnchoredReportsAMismatchedProof(t *testing.T) {
	bin := nornBinary(t)
	log := anchoredLog(t)
	// The sample proof is over an unrelated digest.
	sample, err := os.ReadFile(filepath.Join(vectors(), "anchors", "sample.ots"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(log, "anchors", servedSize(t)+".ots"), sample, 0o644); err != nil {
		t.Fatal(err)
	}

	out, stderr, _ := run(t, bin, "verify", "-trust",
		filepath.Join(vectors(), "trust.cbor"), "-log", log, "-anchored")
	combined := out + stderr
	if !strings.Contains(combined, "different document") {
		t.Errorf("a proof for other bytes should be named as such:\n%s", combined)
	}
}

// anchoredLog is the fixture's served log with its OpenTimestamps proof in
// place, which is the layout SPEC §6 describes: `anchors/<size>.ots`.
func anchoredLog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(vectors(), "served")
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dir, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "anchors"), 0o755); err != nil {
		t.Fatal(err)
	}
	proof, err := os.ReadFile(anchorProof(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchors", servedSize(t)+".ots"), proof, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// --- Cold-model gate run 5, defect G2 (6.5b) -----------------------------
//
// §12.1 claimed the suite refused an unsigned checkpoint, one signed by
// another key, one under another origin, a short quorum, an uncosigned head
// and a forged cosignature. Every one of those was a Go test in this
// repository and none of them was a file. Run 5's implementer therefore built
// a verifier that never checked a note or cosignature signature and passed all
// 597 checks. These are the same refusals, as bytes a second implementer
// actually receives.

func badCheckpointCases(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "checkpoints-bad", "cases.json"))
	if err != nil {
		t.Fatalf("read checkpoints-bad/cases.json: %v", err)
	}
	var doc struct {
		Cases []string `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

// servedWithCheckpoint serves the real log under a checkpoint that must not be
// believed. Everything else about the log is honest, so a refusal can only
// come from the checkpoint.
func servedWithCheckpoint(t *testing.T, checkpoint string) string {
	t.Helper()
	dir := anchoredLog(t)
	body, err := os.ReadFile(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEveryBadCheckpointVectorIsRefused(t *testing.T) {
	cases := badCheckpointCases(t)
	if len(cases) < 8 {
		t.Fatalf("checkpoints-bad ships %d cases; §12.1 names more than that", len(cases))
	}
	bin := nornBinary(t)
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			dir := servedWithCheckpoint(t,
				filepath.Join(vectors(), "checkpoints-bad", name+".checkpoint"))
			out, err := exec.Command(bin, "verify",
				"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", dir).CombinedOutput()
			if err == nil {
				t.Fatalf("accepted %s, which must be refused:\n%s", name, out)
			}
		})
	}
}

// The control: the same harness accepts the honest checkpoint. Without it a
// test that refuses everything would look identical to one that works.
func TestTheHonestCheckpointIsStillAccepted(t *testing.T) {
	dir := servedWithCheckpoint(t, filepath.Join(vectors(), "served", "checkpoint"))
	out, err := exec.Command(nornBinary(t), "verify",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("the honest checkpoint was refused: %v\n%s", err, out)
	}
}

// anchorProof is the fixture's OpenTimestamps proof. Its name carries the tree
// size (§6: `anchors/<size>.ots`), so it is found rather than spelled: four
// entries were added to the fixture in 6.5d-ii and every hardcoded
// `checkpoint-90.ots` went stale at once.
func anchorProof(t *testing.T) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(vectors(), "anchors", "checkpoint-*.ots"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("want exactly one checkpoint proof in anchors/, found %v (%v)", matches, err)
	}
	return matches[0]
}

// servedSize is the tree size the fixture's checkpoint claims. §6 names the
// anchor `anchors/<size>.ots`, so both the file and the name that finds it
// follow the fixture rather than a constant.
func servedSize(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) < 2 {
		t.Fatal("the served checkpoint has no size line")
	}
	return lines[1]
}

// §12.1 named "tampered bundle, missing bundle" for §6 and shipped neither.
// A served directory is not one file, so `served-bad/` ships the replacement
// bytes and says which path to put them at -- or to remove.

func TestEveryServedNegativeIsRefused(t *testing.T) {
	dir := filepath.Join(vectors(), "served-bad")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatalf("the served negatives are missing: %v", err)
	}
	var doc struct {
		Cases []struct {
			Name, Path, File string
			Remove           bool
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 3 {
		t.Fatalf("%d served negatives; §6 has three: a tampered bundle, a missing "+
			"one, and a hash tile that disagrees with the entries", len(doc.Cases))
	}
	bin := nornBinary(t)

	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			log := anchoredLog(t)
			target := filepath.Join(log, filepath.FromSlash(c.Path))
			if c.Remove {
				if err := os.Remove(target); err != nil {
					t.Fatalf("the case removes %s, which the honest log does not serve: %v",
						c.Path, err)
				}
			} else {
				body, err := os.ReadFile(filepath.Join(dir, c.File))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, body, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out, err := exec.Command(bin, "verify",
				"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", log).CombinedOutput()
			if err == nil {
				t.Fatalf("accepted a log serving %s:\n%s", c.Name, out)
			}
		})
	}
}

// Cold-model gate run 6, defect H8. §10's procedure never compared the
// checkpoint's origin line with the network's, and `blind-origin-check` passed
// every vector: `03-wrong-origin` is refused by the note name and key id, not
// by any origin comparison. A checkpoint's origin is the field that says which
// log it is about, and nothing was reading it.
func TestACheckpointForAnotherOriginIsRefusedByTheOriginCheck(t *testing.T) {
	dir := servedWithCheckpoint(t,
		filepath.Join(vectors(), "checkpoints-bad", "10-wrong-body-origin.checkpoint"))
	out, err := exec.Command(nornBinary(t), "verify",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", dir).CombinedOutput()
	if err == nil {
		t.Fatalf("accepted a checkpoint whose origin names another log:\n%s", out)
	}
	if !strings.Contains(string(out), "origin") {
		t.Errorf("refused, but not for its origin -- so the check is still unforced:\n%s", out)
	}
}

// §9.4, and the only vector in the suite with two correct answers.
//
// The same head, signed by a key the log's roots published. A reader holding
// only `trust.cbor` must refuse it -- it has never seen the rotation, and a
// key that vouched for itself would let a stolen log key name its successor. A
// reader that has replayed this log has learned the key and must accept it.
func TestTheRotatedHeadIsRefusedUntilItsRotationIsReplayed(t *testing.T) {
	dir := servedWithCheckpoint(t, filepath.Join(vectors(), "served-rotated", "checkpoint"))
	bin := nornBinary(t)

	out, err := exec.Command(bin, "verify",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", dir).CombinedOutput()
	if err == nil {
		t.Fatalf("a one-shot verify accepted a head signed by a key the trust file does "+
			"not name and this run never replayed:\n%s", out)
	}
	if !strings.Contains(string(out), "not signed by a key this anchor trusts") {
		t.Errorf("refused, but not for the signature:\n%s", out)
	}

	// The honest head over the same tiles still verifies, so the difference is
	// the signing key and nothing else about the directory.
	if out, err := exec.Command(bin, "verify",
		"-trust", filepath.Join(vectors(), "trust.cbor"),
		"-log", servedWithCheckpoint(t, filepath.Join(vectors(), "served", "checkpoint")),
	).CombinedOutput(); err != nil {
		t.Fatalf("the honest head over the same tiles was refused: %v\n%s", err, out)
	}
}

// §9.4's policy half, from the other direction: here the *uninformed* reader
// accepts. A one-shot verify holds only the trust file, which requires two of
// three witnesses, and this head has two. A node that had replayed the roots
// raising the quorum to three would refuse it -- which is what the agent test
// covers, because only a node that keeps running has seen the rotation.
func TestTheSupersededHeadSatisfiesTheTrustFilesPolicy(t *testing.T) {
	dir := servedWithCheckpoint(t, filepath.Join(vectors(), "served-superseded", "checkpoint"))
	out, err := exec.Command(nornBinary(t), "verify",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("a reader holding only the trust file refused a head that meets its "+
			"own policy: %v\n%s", err, out)
	}
}

// --- Cold-model gate run 7, defect J4 -----------------------------------
//
// §6 says the served `tile/<L>/…` hashes "MUST also agree with the tree it
// rebuilt" and that "checking them is not optional". `served-bad/` held two
// cases and both were *entry bundle* cases, so nothing in the suite ever
// opened a hash tile: run 7's `blind-tiles` variant never fetched `tile/0/…`
// at all and passed 241/241.
//
// The rule is not about reaching the head -- the entries alone do that. It is
// about a node serving onward what it fetched: a log with a corrupt hash tile
// is broken for every peer that asks it for a proof, and the node that relays
// it is the one that made it so.

func TestATamperedHashTileIsRefusedByTheTileRule(t *testing.T) {
	dir := filepath.Join(vectors(), "served-bad")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name, Path, File string
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range doc.Cases {
		if !strings.HasPrefix(c.Path, "tile/") || strings.HasPrefix(c.Path, "tile/entries/") {
			continue
		}
		found = true
		t.Run(c.Name, func(t *testing.T) {
			log := anchoredLog(t)
			body, err := os.ReadFile(filepath.Join(dir, c.File))
			if err != nil {
				t.Fatal(err)
			}
			// The entry bundles stay honest, so the tree the verifier rebuilds
			// still matches the signed head. Only the tile rule can refuse it.
			if err := os.WriteFile(filepath.Join(log, filepath.FromSlash(c.Path)),
				body, 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(nornBinary(t), "verify",
				"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", log).CombinedOutput()
			if err == nil {
				t.Fatalf("accepted a log whose hash tile is not what its entries imply:\n%s", out)
			}
			if !strings.Contains(string(out), c.Path) {
				t.Errorf("refused, but not by the tile rule -- the message never names "+
					"%s:\n%s", c.Path, out)
			}
		})
	}
	if !found {
		t.Fatal("no hash-tile negative in served-bad/: §6's tile MUST is unpinned, " +
			"and a verifier that never opens tile/0/… is indistinguishable from one that does")
	}
}

// --- Cold-model gate run 7, defect J12 ----------------------------------
//
// §10 says "every cosignature by a witness the policy names must verify" and
// §5.3 says "two verifying lines from the same witness with different
// timestamps are its newest". Between them they never settled the case where
// one witness supplies **both**: a reader that picks each witness's newest
// *verifying* line sees three good witnesses and carries on, and one that
// checks every line refuses. Run 7's `cosig-all-lines` passed either way,
// because no checkpoint in the suite carried two lines from one witness.
//
// `11-forged-cosignature-with-quorum` is the neighbouring case and cannot
// stand in: there the bad line's witness has no good line, so declining to
// count it still leaves a quorum of two rather than a quorum of three.

func TestACheckpointWithTwoLinesFromOneWitnessIsRefused(t *testing.T) {
	const name = "12-second-line-from-one-witness"
	path := filepath.Join(vectors(), "checkpoints-bad", name+".checkpoint")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("§10's per-line rule has no vector: %v", err)
	}

	// The case only pins the rule if one witness really does sign twice, and
	// if dropping the bad line would leave a satisfied quorum.
	counts := map[string]int{}
	for _, line := range strings.Split(strings.TrimRight(string(body), "\n"), "\n") {
		if rest, ok := strings.CutPrefix(line, "— "); ok {
			counts[strings.Fields(rest)[0]]++
		}
	}
	var twice string
	for who, n := range counts {
		if n > 1 && strings.Contains(who, "witness") {
			twice = who
		}
	}
	if twice == "" {
		t.Fatal("no witness signs twice, so a per-witness reader and a per-line one " +
			"reach the same answer and the vector pins nothing")
	}
	distinct := 0
	for who := range counts {
		if strings.Contains(who, "witness") {
			distinct++
		}
	}
	if distinct < 3 {
		t.Errorf("%d distinct witnesses; the other two must already satisfy the "+
			"quorum, or ignoring the bad line refuses anyway", distinct)
	}

	dir := servedWithCheckpoint(t, path)
	out, err := exec.Command(nornBinary(t), "verify",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", dir).CombinedOutput()
	if err == nil {
		t.Fatalf("accepted a checkpoint carrying a cosignature line that does not "+
			"verify, masked by a good line from the same witness:\n%s", out)
	}
}

// --- Cold-model gate run 8, defect D21 ----------------------------------
//
// §7 restates the signed-note format "so an implementer needs nothing else",
// and four of its framing rules were enforced by both implementations and
// vectored by neither: the em-dash prefix, the newline ending the signature
// block, a canonical decimal size line, and how many signature lines a
// checkpoint may carry under the log's key.
//
// None of them is exotic. An ASCII hyphen instead of U+2014 is what a reader
// writes if they never look at the bytes, and a checkpoint with two log
// signatures -- one valid, one not -- is the same shape as the per-line
// cosignature rule §10 already settles.

func TestEveryNoteFramingRuleHasACheckpointCase(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectors(), "checkpoints-bad", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []string `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, name := range doc.Cases {
		have[name] = true
	}
	for _, want := range []string{
		"13-ascii-dash-signature",
		"14-unterminated-signature-block",
		"15-size-leading-zero",
		"16-two-log-signatures",
	} {
		if !have[want] {
			t.Errorf("§7 states this and `checkpoints-bad/%s` does not ship, so a "+
				"reader that frames notes differently reproduces the whole suite", want)
		}
	}
}

// --- Cold-model gate run 9, defect D17 ----------------------------------
//
// §10 says every cosignature line naming a witness the policy lists must
// verify. It says nothing about a line naming a key the reader does not know
// -- and `07-unnamed-witness-only` is refused either way, for want of a
// quorum, so the suite could not separate "ignore it" from "refuse over it".
//
// It is not cosmetic. A witness cosigning a log this node's policy does not
// list is normal in a shared log: the moment one appears, the refusing
// implementation stops accepting checkpoints everybody else accepts.
//
// The rule is **ignore**. `served-extra-witness/` is the honest head with one
// more line from a witness the policy never names, and it MUST be accepted.

func TestACheckpointWithAnUnknownCosignerIsAccepted(t *testing.T) {
	dir := filepath.Join(vectors(), "served-extra-witness")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatalf("§10 says nothing about an unknown signature line and no vector "+
			"reaches it: %v", err)
	}
	var doc struct {
		ServeOver string `json:"serve_over"`
		Stranger  string `json:"stranger"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	signed, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	// The case only pins the rule if the extra line really is from a witness
	// the policy does not name.
	if !strings.Contains(string(signed), doc.Stranger) {
		t.Fatalf("the head carries no line from %s", doc.Stranger)
	}
	anchor, err := os.ReadFile(filepath.Join(vectors(), "trust.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(anchor), doc.Stranger) {
		t.Fatalf("%s is in the trust file, so the policy does know it", doc.Stranger)
	}

	log := servedWithCheckpoint(t, filepath.Join(dir, "checkpoint"))
	out, err := exec.Command(nornBinary(t), "verify",
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-log", log).CombinedOutput()
	if err != nil {
		t.Fatalf("refused a checkpoint whose only oddity is a cosignature from a "+
			"witness this policy does not name; §10 ignores such a line:\n%s", out)
	}
}
