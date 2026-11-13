package docclaims

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Cold gate run 22 (rows G28 to G30): every sentence its findings need, D1
// (G28: text only, every build already replays to the stored checkpoint) and
// D2, D3, D5, D7, D8, D9, D12, D13, D14 and D15 (G29's sort), and the old
// wording gone.
func TestRunTwentyTwosSentencesAreInTheSpecification(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	spec := string(raw)
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	section := func(t *testing.T, from, to string) string {
		t.Helper()
		start := strings.Index(spec, from)
		if start < 0 {
			t.Fatalf("SPEC.md has no %q", from)
		}
		end := strings.Index(spec[start+len(from):], to)
		if end < 0 {
			t.Fatalf("SPEC.md has no %q after %q", to, from)
		}
		return flat(spec[start : start+len(from)+end])
	}
	for _, tc := range []struct {
		name, from, to string
		want, stale    []string
	}{
		{
			name: "§7 the library differs in two places (D13), names compare byte for byte (D8), a key name's bound (D12)",
			from: "## 7. Submission and receipts", to: "## 8. Proof bundles",
			want: []string{
				"They differ in two places. One is where the text ends: that library ends it at the *last* blank line, this document at the first (the first bullet below), and the two answer differently only for a note with a second blank line. The other is §10's rule that every signature line matching a trusted key must verify, which Norn imposes and that library does not (`checkpoints-bad/16-two-log-signatures`).",
				"Names and key ids are compared byte for byte: a line whose name differs from a trusted key's only in case, such as `NORN-WITNESS/PI`, matches no trusted key and is ignored like any stranger's (`served-upper-witness-name/`, `served-upper-log-name/`, cold gate run 22, D8).",
				"A key name has no length limit of its own: the byte cap of the artifact that carries it still applies, and the 64-byte limit is §9.1's, on a policy's witness and group names, not on the key names inside their verifier keys (`trust-good/long-witness-key-name`, cold gate run 22, D12).",
			},
			stale: []string{"They differ in one place, where the text ends"},
		},
		{
			name: "§8.1 condition 3 names the node's stored checkpoint (D1)",
			from: "### 8.1 Bundle format", to: "## 9. Trust file",
			want: []string{
				"3. replay of the log up to **the node's stored checkpoint** — not the bundle's, which condition 2 has shown to be consistent with it, older or newer — yields the device as `active`, and the key the node installs for it is **the `wg_pk` replay gives**: the device's current key in the §5.3 state, never the key written in the bundle's entry, and",
				"Condition 3 never replays past the stored checkpoint. A bundle is usually older than the node's head, and replay to the stored checkpoint is what keeps a device revoked, or a key rotated, since the bundle's head out of the interface: `proofs-older-head/` ships two bundles at a size-10 head of `served/` with the keys each reading would install (cold gate run 22, D1). A bundle may also be newer than the node's head and prove an entry the node has not replayed; the node installs nothing on that entry's account until it has accepted such a checkpoint itself (§10).",
			},
			stale: []string{"3. replay of the log up to that checkpoint yields the device as `active`"},
		},
		{
			name: "§9.1 policy names compare byte for byte (D9)",
			from: "### 9.1 CBOR fields", to: "### 9.2 TOML rendering",
			want: []string{"each name is defined **once**, and a repeat is an error. Names compare byte for byte and nothing is case-folded: `pi` and `PI` are two names (`policies/names-differ-in-case.txt`, cold gate run 22, D9)."},
		},
		{
			name: "§10.1 step 6 under quorum none (D7)",
			from: "### 10.1 Refusal codes", to: "## 11. Fork handling",
			want:  []string{"a cosignature line whose name **and** key id match a listed witness does not verify, whatever the quorum requires, `none` included (§9.1, `quorum-none/forged-pi.checkpoint`) — listed meaning named by the policy that applies"},
			stale: []string{"a cosignature line whose name **and** key id match a listed witness does not verify — listed meaning"},
		},
		{
			name: "§12 the genesis row isolates stated refusals (D3)",
			from: "## 12. Test vectors", to: "### 12.1 Coverage",
			want:  []string{"each refused `bad-genesis` and each isolating one stated entry-0 refusal"},
			stale: []string{"one per way entry 0 can abort"},
		},
		{
			name: "§12.1 genesis signers' admission (D2) and what replayed_policy_quorum_time is (D5)",
			from: "### 12.1 Coverage", to: "## 13. Node enforcement",
			want: []string{
				"including both key arrays of a genesis — `genesis/23-root-order-eight` holds `roots` and `genesis/28-signer-order-eight` holds `signers` (cold gate run 22, D2) — a `rotate`'s incoming `device_pk` and a `policy` entry's witness key (D-075).",
				"`replayed_policy_quorum_time` 1760003600 is the `T` a reader computes for that checkpoint once it has replayed that policy and holds no checkpoint (§9.4): the time of a later read, never a substitute for the first acceptance's (cold gate run 22, D5).",
			},
			stale: []string{
				"in the rows above), including a `rotate`'s incoming `device_pk`",
				"pins the different, retroactive reading",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := section(t, tc.from, tc.to)
			for _, want := range tc.want {
				if !strings.Contains(text, flat(want)) {
					t.Errorf("SPEC.md must say, in the section from %q:\n%s", tc.from, want)
				}
			}
			for _, stale := range tc.stale {
				if strings.Contains(text, flat(stale)) {
					t.Errorf("SPEC.md still says, in the section from %q:\n%s", tc.from, stale)
				}
			}
		})
	}
}

// D14 and D15: the two provenance statements agree with each other and with
// what the Makefile says each generator writes, and the vectors README's
// `log-cas/` row describes `log-cas/`.
func TestRunTwentyTwosProvenanceAgreesWithTheMakefile(t *testing.T) {
	read := func(path ...string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, path...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	m := regexp.MustCompile(`(?m)^GO_VECTOR_DIRS := (.+)$`).FindStringSubmatch(read("Makefile"))
	if m == nil {
		t.Fatal("the Makefile has no GO_VECTOR_DIRS")
	}
	goDirs := strings.Fields(m[1])

	spec := read("SPEC.md")
	start := strings.Index(spec, "**Four provenances, stated plainly.**")
	if start < 0 || strings.Contains(spec, "**Three provenances, stated plainly.**") {
		t.Fatal("§12 must state four provenances, as the vectors README does (cold gate run 22, D14)")
	}
	end := strings.Index(spec[start:], "\n\n")
	paragraph := flat(spec[start : start+end])

	readme := read("testdata", "vectors", "README.md")
	row := func(prefix string) string {
		for _, line := range strings.Split(readme, "\n") {
			if strings.HasPrefix(line, prefix) {
				return line
			}
		}
		t.Fatalf("the vectors README has no row starting %q", prefix)
		return ""
	}
	goRow := row("| **`cmd/norn-genlog`**")
	refRow := row("| **`contrib/norn-ref`**")

	for _, dir := range goDirs {
		name := "`" + dir + "/`"
		if !strings.Contains(paragraph, name) {
			t.Errorf("§12's provenance paragraph does not name %s, which `make vectors-log` writes", name)
		}
		if !strings.Contains(goRow, name) {
			t.Errorf("the vectors README's Go row does not name %s, which `make vectors-log` writes", name)
		}
		if strings.Contains(refRow, name) {
			t.Errorf("the vectors README's reference row names %s, which Go writes", name)
		}
	}
	// `receipt-bad/` is the reference's alone: nothing in cmd/norn-genlog
	// writes a receipt.
	if strings.Contains(goRow, "receipt-bad") {
		t.Error("the vectors README's Go row still credits Go with the `receipt-bad/` extension")
	}
	for _, s := range []string{paragraph, refRow} {
		if !strings.Contains(s, "`receipt-bad/`") {
			t.Errorf("the reference's receipts must be named among its vectors: %.120s", s)
		}
	}
	for _, s := range []string{"`anchors/`", "`ed25519-cctv/`", "C2SP"} {
		if !strings.Contains(paragraph, s) {
			t.Errorf("§12's provenance paragraph must name %s", s)
		}
	}

	if strings.Contains(row("| `log-cas/`"), "run 17 restores root3") {
		t.Error("the vectors README's `log-cas/` row still describes `log-rules/19`–`25` (cold gate run 22, D15)")
	}
}
