package specdoc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cold gate run 14 found prose that misstated existing implementation rules.
// Keep each correction in its section and keep generated hints about the rule
// as a whole, since no artifact can isolate the canonical point clauses.
func TestRunFourteensProseFindingsAreFixed(t *testing.T) {
	doc := load(t)
	for _, tc := range []struct{ section, name, want, stale string }{
		{"4.0", "Device IDs match the whole string", "| `device_id` | matches `^[a-z0-9][a-z0-9.-]{0,63}$` **as a whole** — `\\A…\\z`, every byte of the string. An engine whose `$` also matches before a final newline accepts `nas2\\n`; §2's rule is over the string, and both implementations here refuse it (cold gate run 14, H2) |", "| `device_id` | matches `^[a-z0-9][a-z0-9.-]{0,63}$` |"},
		{"10.1", "Zero length frames and full bundle trailing bytes have their own refusals", "| 8 | `entries` | the entry bundles the checkpoint's size implies do not frame (§6's big-endian uint16 length prefixes), or do not add up to that size. A zero-length frame **frames** — a uint16 length of 0 is a frame — and the empty entry it carries is §5.1's `decode`: a rejected entry in an accepted log, not this code. Bytes after the last frame a full bundle needs are either further frames, which do not add up, or a truncated one, which does not frame: this code either way (run 14, M2 and M3) |", "| 8 | `entries` | the entry bundles the checkpoint's size implies do not frame (§6's big-endian uint16 length prefixes), or do not add up to that size |"},
		{"10.1", "Hash tiles agree in bytes and length", "| 12 | `tiles` | a served hash tile disagrees with the rebuilt tree — compared byte for byte, length included: a tile of width `W` is exactly 32 × `W` bytes, and a longer or shorter one disagrees whatever its first 32 × `W` bytes say (run 14, M3) |", "| 12 | `tiles` | a served hash tile disagrees with the rebuilt tree |"},
		{"10.1", "Missing hash tiles are reported at step 12", "an entry bundle (step 8), a hash tile (step 12) — reported at that step |", "an entry bundle (step 8), a hash tile (step 11) — reported at that step |"},
		{"3.1", "Canonical clauses are implied by the order clause", "2, 4 or 8 — `[L]P = O` and `P ≠ O`. The two canonical clauses are implied by the order clause — every `y` at or above `p` decodes, read leniently, off the curve or to a point of non-prime order, and `x` is 0 only at the identity and the point of order 2 — and are stated because libraries decode differently; no artifact can isolate them, so `genesis/24-root-noncanonical` and `trust-bad/47-witness-noncanonical-point` pin this item, not the clause they were named for (run 14, L3). An honest key `[s]B` and an honest", "2, 4 or 8 — `[L]P = O` and `P ≠ O`. An honest key `[s]B` and an honest"},
		{"12.1", "Trust algorithm vectors also exercise the policy rule", "**`15`** and **`16`** parse cleanly as verifier keys and are refused by the algorithm rule — the trust file's, and the policy grammar's again once the key enters the policy, so neither isolates the trust-level rule alone (run 14, L4);", "**`15`** and **`16`** parse cleanly as verifier keys and are refused only by the algorithm rule;"},
		{"12.1", "Allowed IP intersection needs a live reconciliation test", "- §13's interface reconciliation and `proven.json` publication cannot be\n  demonstrated by the static protocol vectors, §13.1's intersection of a\n  peer's allowed-ips with its grant included.", "- §13's interface reconciliation and `proven.json` publication cannot be\n  demonstrated by the static protocol vectors."},
		{"12.1", "Canonical clauses are admitted as unvectorable", "  imply the guarantee §5.2 gives.\n- **§3.1's canonical clauses.** \"`y` below `p`\" and \"the sign bit is 0 when\n  `x` is 0\" are implied by `[L]P = O ∧ P ≠ O` — checked by computation over\n  every `y` in [p, 2²⁵⁵) and both `x = 0` points — so a reader that skips them\n  and keeps the order clause is indistinguishable on every artifact,\n  `genesis/24-root-noncanonical` and `trust-bad/47-witness-noncanonical-point`\n  included, which pin item 1 as a whole (run 14, L3).\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			section, ok := doc.Section(tc.section)
			if !ok {
				t.Fatalf("§%s is missing", tc.section)
			}
			body := strings.Join(strings.Fields(section.Body), " ")
			if !strings.Contains(body, strings.Join(strings.Fields(tc.want), " ")) {
				t.Errorf("§%s lacks run 14 passage %q", tc.section, tc.want)
			}
			if tc.stale != "" && strings.Contains(body, strings.Join(strings.Fields(tc.stale), " ")) {
				t.Errorf("§%s retains replaced passage %q", tc.section, tc.stale)
			}
		})
	}
	// §12's trust-bad count is read from the suite rather than pinned: run 14
	// found it stale (L5), and a pinned number goes stale the next time a
	// trust file is added, which D-077 did the same day.
	t.Run("The trust file count matches the suite", func(t *testing.T) {
		var manifest struct {
			Cases []string `json:"cases"`
		}
		readJSON(t, filepath.Join(vectorRoot(t), "trust-bad", "cases.json"), &manifest)
		section, ok := doc.Section("12")
		if !ok {
			t.Fatal("§12 is missing")
		}
		want := fmt.Sprintf("| %d trust files, including `47-witness-noncanonical-point`,", len(manifest.Cases))
		if !strings.Contains(section.Body, want) {
			t.Errorf("§12 does not say %q: trust-bad ships %d cases", want, len(manifest.Cases))
		}
	})
	t.Run("The vectors README names every closed code list", func(t *testing.T) {
		path := filepath.Join(vectorRoot(t), "README.md")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		body := strings.Join(strings.Fields(string(raw)), " ")
		want := "§5.2, §7, §10.1 and §11.1 each give their layer a closed list of codes, and a\nmanifest's `codes` map is what to compare against (§12); `says` is for the rules\nthat have none: map each onto your own error by hand, once."
		stale := "§5.2 gives replay a closed list of reason codes and\nno other layer has one, so outside replay there is nothing to compare: map each\n`says` onto your own error by hand, once."
		if !strings.Contains(body, strings.Join(strings.Fields(want), " ")) {
			t.Errorf("%s lacks run 14 paragraph %q", path, want)
		}
		if strings.Contains(body, strings.Join(strings.Fields(stale), " ")) {
			t.Errorf("%s retains replaced paragraph %q", path, stale)
		}
	})
	t.Run("The generated missing hash tile hint names step 12", func(t *testing.T) {
		path := filepath.Join(vectorRoot(t), "served-bad", "cases.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(raw), "step 12 needs the hash tile") {
			t.Errorf("%s lacks %q", path, "step 12 needs the hash tile")
		}
		if strings.Contains(string(raw), "step 11") {
			t.Errorf("%s still names step 11 for the hash tile", path)
		}
	})
	for _, tc := range []struct{ dir, name string }{
		{"genesis", "24-root-noncanonical"},
		{"trust-bad", "47-witness-noncanonical-point"},
	} {
		t.Run(tc.name+" pins the whole point rule", func(t *testing.T) {
			path := filepath.Join(vectorRoot(t), tc.dir, "cases.json")
			var manifest struct {
				Rules map[string]struct{ Section, Says string }
			}
			readJSON(t, path, &manifest)
			rule := manifest.Rules[tc.name]
			const want = "of a point of order exactly `L` on edwards25519"
			if rule.Section != "3.1" || rule.Says != want {
				t.Errorf("%s: %s must cite §3.1 with says %q; got %+v", path, tc.name, want, rule)
			}
		})
	}
}
