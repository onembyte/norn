package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cold gate run 21 (rows G24 to G26): every sentence its findings need, M1 and
// M2 (G24: text only, Go already right) and L2, L5 and L7 (G25's sort), and
// the old wording gone.
func TestRunTwentyOnesSentencesAreInTheSpecification(t *testing.T) {
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
			name: "§4.3 a note's text is required (L2)",
			from: "### 4.3 Types and bodies", to: "#### Why `enroll` embeds",
			want: []string{"`text` is required in a `note` body. An empty string is valid; an absent `text` is `decode` (§4.0)."},
		},
		{
			name: "§8.1 binding names after and prev (L5)",
			from: "### 8.1 Bundle format", to: "## 9. Trust file",
			want:  []string{"its closed set of members, each of its type: `v` 1, a text `t`, a 16-byte `net`, a uint `ts`, a map `body`, well-formed `sigs`, and a uint `after` and `prev` where present — or it names no device"},
			stale: []string{"a map `body`, well-formed `sigs` — or it names no device"},
		},
		{
			name: "§10.1 step 6 names the policy that applies to a held head (M1)",
			from: "### 10.1 Refusal codes", to: "## 11. Fork handling",
			want:  []string{"listed meaning named by the policy that applies — the policy in force (§9.4), or, for a re-read of the tree head the reader already holds, the policy that accepted it (§5.3, D-084 (1)) — not a witness that policy has dropped and the trust file still lists"},
			stale: []string{"listed meaning named by the policy in force (§9.4), not a witness a `policy` entry has dropped that the trust file still lists"},
		},
		{
			name: "§11.1 the split root at a head's own size (M2)",
			from: "### 11.1 Evidence format", to: "## 12. Test vectors",
			want: []string{
				"a split proof does not chain `split_root` at `split` to its head, `split_root` is not the root a head is signed over where `split` equals that head's size, or a split proof is carried where none is required (step 4)",
				"each as step 3 does, with the same rule at a head's own size: no proof, and `split_root` equal to the root that head is signed over.",
			},
			stale: []string{
				"a split proof does not chain `split_root` at `split` to its head, or a split proof is carried where none is required (step 4)",
				"with the same empty-proof rule at a head's own size.",
			},
		},
		{
			name: "§12 an informed reader holds no checkpoint unless a case says so (L7)",
			from: "## 12. Test vectors", to: "### 12.1 Coverage",
			want: []string{
				"An informed reader has learned the keys and the policy a case names by replaying the entries the case gives; that alone does not make it hold a checkpoint. In `served-rotated-earlier/` and `dropped-witness/` the informed reader holds none, so those cases isolate the use of a learned key or policy from §10's comparison with a stored head: a reader that holds `served/`'s head refuses the shorter `served-rotated-earlier/` log as `rollback`. `held-policy/` states its two readers' histories in its `cases.json`.",
				"`cases.json` gives `fresh` as `log-signature` and `informed`, a reader holding no checkpoint, as `accept`",
			},
			stale: []string{"`cases.json` gives `fresh` as `log-signature` and `informed` as `accept`"},
		},
		{
			name: "§12.1 rows and omissions (L2, L7)",
			from: "### 12.1 Coverage", to: "## 13. Node enforcement",
			want: []string{
				"`text` is required and bounded above only; `reason` is 0–256 bytes and OPTIONAL (§4.3). An empty value and an absent member are different questions: `log-rules/55-note-without-text` is `decode`",
				"`served-rotated-earlier/`: an informed reader holding no checkpoint accepts the 20-entry head",
				"- §13's interface reconciliation and `proven.json` publication cannot be demonstrated by the static protocol vectors. §13.1's grant bound and overlap rule are pure functions a table could pin, as `proven/grant-labels.json` pins a grant's spelling; none ships yet, and the Go endpoint tests hold both (cold gate run 21, L7). `detect/staleness.json` pins",
				"- **The separate `split` ≤ `size` check (§11.1).** The conflicting head's size must equal `size`, and a split proof cannot chain from a size above its head, so `fork/bad-split-above-size` holds the `proof` outcome without isolating a bound check of its own (cold gate run 21, L7).",
				"- **The trust file's own witness algorithm and name rules (§9.1).** Correspondence puts each witness's key and short name into the policy, whose grammar checks them again: `trust-bad/15-witness-key-is-a-note-key`, `32-witness-name-too-long` and `54-witness-name-not-ascii` hold the refusals, not the trust-level checks alone (cold gate run 21, L7).",
				"- **The subgroup check on `R` under the cofactorless equation (§3.1).** With a valid `A`, that equation already puts `R` in the subgroup of order `L`, so a reader that keeps every other check on `R` and drops only that one cannot be told apart. The rest of the rule on `R` is not implied: the equation admits an identity `R`, and `ed25519-cctv/` vector 304 (`low_order_R`) is refused (cold gate run 21, L7).",
			},
			stale: []string{
				"`text` is bounded above only, `reason` is 0–256, and §4.3 marks it OPTIONAL",
				"`served-rotated-earlier/`: an informed reader accepts the 20-entry head",
				"§13.1's grant bound and overlap rule included.",
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
	// The three new omissions sit together, before run 16's list, in order.
	t.Run("§12.1 the omissions' order", func(t *testing.T) {
		text := section(t, "### 12.1 Coverage", "## 13. Node enforcement")
		at := func(s string) int { return strings.Index(text, flat(s)) }
		a, b, c, d := at("- **The separate `split` ≤ `size` check (§11.1).**"), at("- **The trust file's own witness algorithm and name rules (§9.1).**"), at("- **The subgroup check on `R` under the cofactorless equation (§3.1).**"), at("- **Rules stated plainly that no vector holds yet (cold gate run 16, L8).**")
		if a < 0 || !(at("- **Two distinct keys with the same `kid`.**") < a && a < b && b < c && c < d) {
			t.Error("the three omissions go after run 20's two and before run 16's list, in this order")
		}
	})
}
