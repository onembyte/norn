package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-084 (row G19) and run 20's last sentences (G18's L2 to L7): the
// specification says what the owner decided on 2026-11-11 and what Go and the
// reference already do, and the old sentences are gone.
func TestRunTwentysDecisionsAndSentencesAreInTheSpecification(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	spec := read("SPEC.md")
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
		return spec[start : start+len(from)+end]
	}
	for _, tc := range []struct {
		name, from, to string
		exact          bool // compare bytes, line breaks included (a code block)
		want           []string
		stale          []string
	}{
		{
			name: "§4.0 genesis kids are distinct (M3)",
			from: "### 4.0 Encoding profile", to: "### 4.1 Envelope",
			want:  []string{"| `roots`, `signers` at genesis | arrays of 32-byte `pk`, no duplicates, no key in both, and no two keys with the same `kid(pk)`, within an array or across the two (D-084 (4)); `len(roots) ≥ root_thr ≥ 1`; `len(signers) ≥ signer_thr ≥ 1` |"},
			stale: []string{"| `roots`, `signers` at genesis | arrays of 32-byte `pk`, no duplicates, no key in both; `len(roots)"},
		},
		{
			name: "§4.3 points to §13.1 for overlaps (M2)",
			from: "### 4.3 Types and bodies", to: "#### Why `enroll` embeds",
			want:  []string{"What a node installs for two peers whose allowed-ips overlap is not a replay rule; §13.1 states it: neither peer is given an overlapping prefix, and the pair is reported."},
			stale: []string{"`ENFORCEMENT.md` narrates how `nornd` gives neither peer the overlapping prefix and reports the pair."},
		},
		{
			name: "§5.1 step 6 genesis kids are distinct (M3)",
			from: "### 5.1 Procedure", to: "### 5.2 Reason codes",
			want:  []string{"6. Body checks: `roots` and `signers` are non-empty arrays of distinct 32-byte keys, disjoint from each other, and no two keys within or across them share a `kid(pk)` (D-084 (4)); `1 ≤ root_thr ≤ len(roots)`;"},
			stale: []string{"keys, disjoint from each other; `1 ≤ root_thr ≤ len(roots)`;"},
		},
		{
			name: "§5.3 a re-read of the held head checks its lines (D-084 (1))",
			from: "### 5.3 Canonical state schema", to: "## 6. The log",
			want:  []string{"from a peer, changes neither (D-082 (1)). The copy's own lines are still checked as §10 checks every checkpoint: a cosignature line that names a witness that policy lists, by name and key id, and does not verify refuses the read as `cosignature`. The copy's quorum is not judged again and nothing from the copy is stored, so a copy with fewer valid lines than the policy needs is still the held head (D-084 (1)). That is the verifier loop's held head (§10)"},
			stale: []string{"changes neither (D-082 (1)). That is the verifier loop's held head"},
		},
		{
			name: "§8.1 condition 1 names the policy in force (L6)",
			from: "### 8.1 Bundle format", to: "## 9. Trust file",
			want:  []string{"1. the bundle's checkpoint verifies under the policy in force — the trust file's, or the most recently replayed (§9.4) — even when it names the tree head the node already holds (§5.3), and"},
			stale: []string{"verifies under the node's trust policy (§9), and"},
		},
		{
			name: "§10 the name and key id match does not authenticate a line (L5), and a held head's lines are checked (D-084 (1))",
			from: "## 10. Verifier procedure", to: "### 10.1 Refusal codes",
			exact: true,
			want: []string{
				"      # other key names nobody: it is a stranger's line and is ignored, not a\n" +
					"      # listed witness's line that fails to verify. A node matching on the\n" +
					"      # name alone would refuse an honest stranger who reuses a listed name\n" +
					"      # under another key; `served-name-collision/` is that checkpoint and it\n" +
					"      # MUST be accepted. Matching both does not authenticate a line: anyone\n" +
					"      # who can add bytes on the way can copy a listed witness's name and key\n" +
					"      # id onto a forged line, which is then that witness's line, fails to\n" +
					"      # verify, and is refused as `cosignature`, even beside a valid quorum\n" +
					"      # (`checkpoints-bad/11`). Whoever can add that line can as well withhold\n" +
					"      # the checkpoint, so it gives them nothing they did not have.\n",
				"      # signature line may appear anywhere in the block; order carries nothing.\n" +
					"      # The tree head this node already holds (§5.3), read again: every line\n" +
					"      # is checked as above, under the policy that accepted it, but the quorum\n" +
					"      # is not judged again, and the stored note, cosignatures and `T` stand\n" +
					"      # (D-082 (1), D-084 (1)).\n",
			},
			stale: []string{"The other reading hands\n      # anyone a veto"},
		},
		{
			name: "§12 served-superseded carries the forged copy (P12)",
			from: "## 12. Test vectors", to: "### 12.1 Coverage",
			want:  []string{"| `served-superseded/` | the served head cosigned by two of three witnesses, read fresh and by a reader holding `served/`'s head: both accept, and the held head keeps its `T` (§5.3, D-082 (1)); and `forged-pi.checkpoint`, `served/`'s head with pi's cosignature altered: `cosignature` for both readers, and the reader holding the head keeps `served/`'s note, cosignatures and `T` (D-084 (1)). Serve each over `served/`'s tiles |"},
			stale: []string{"keeps its `T` (§5.3, D-082 (1)). Serve it over `served/`'s tiles |"},
		},
		{
			name: "§12.1 rows and omissions (P12, L2, L3, L4, L5, M1, M2, M3)",
			from: "### 12.1 Coverage", to: "## 13. Node enforcement",
			want: []string{
				"| §5.3, §9.4 a held head keeps its acceptance, and its lines are checked (D-082 (1), D-084 (1)) |",
				"A larger head still faces the latest replayed policy, covered by the agent tests. `forged-pi.checkpoint` is the held head with pi's line altered: `cosignature` for the reader holding it, as for a fresh one, and that reader's stored note, cosignatures and `T` unchanged. Without it, a reader that skips the lines of a held head passed every check (cold gate run 20, L1.10) |",
				"so a decoder that stops at the end of the item answers `dup-entry`, not `decode`: its signed content is that of the entry already applied (cold gate run 20, L3) |",
				"| §5.1 entry 0 records its applied content (run 16, L1) |",
				"changing its `entry_hash` while preserving its `content_hash`: `dup-entry`, before `dup-genesis`. It isolates the content key, not entry 0's byte key (cold gate run 20, L2) |",
				"Step 1's first stated property is `bad-repeat-of-undecodable` (the key is recorded **before** the entry is decoded, so a copy of one that never decoded is `dup-entry` and not a second `decode`). `bad-repeat-of-genesis`, a byte copy of entry 0, is `dup-entry` and not `dup-genesis`; entry 0's content key already gives that answer, so it does not isolate entry 0's byte key (What is not vectored, below; cold gate run 20, L2).",
				"§10 matches a cosignature line on name **and** key id so that an honest stranger reusing a listed name is ignored, not refused; that match does not authenticate a line, only its signature does. The origin comparison is the same care from the other side, where a loose match would hand an attacker an acceptance (cold gate run 11, D7; run 20, L5) |",
				"- §13's interface reconciliation and `proven.json` publication cannot be demonstrated by the static protocol vectors. §13.1's grant bound and overlap rule are pure functions a table could pin,",
				"- **Entry 0's byte key, as distinct from its content key (§5.1 step 1).** A genesis that applies records its content key as well, and one that does not apply aborts replay before another entry is judged, so no input tells a reader that records entry 0's `entry_hash` from one that records only its `content_hash` (cold gate run 20, L2).",
				"- **`entry_hash` being over the bytes *as received* rather than a re-canonicalised form**, the byte key every entry records (D-078), and the only key of one that does not decode. §5.1 step 1's *ordering* is vectored — a copy of an entry that never decoded is `dup-entry` — and so is the lenient reading: a reader that decodes leniently and hashes a re-encoding answers `dup-entry` on `log/60-bad-trailing-byte`, `73-bad-indefinite-map`, `74-bad-duplicate-map-key` and `75-bad-cbor-nonshortest-length`, which are `decode`, and refuses `log-republish/14-params-canonical-true`, which applies after its refused non-canonical twin `13-params-two-byte-true` (cold gate run 20, L4). What no input can show is a reader that admits only deterministic CBOR and then re-encodes: whatever it admitted re-encodes to the same bytes.",
				"- **Two distinct keys with the same `kid`.** The suite holds no two valid Ed25519 public keys whose `kid`s collide, so it cannot isolate genesis's distinct-`kid` rule (§5.1 step 6) or a `signer_add` or `root_add` that compares key bytes where §5.1 compares `kid`s (`dup-key`). Such a pair takes a birthday search of the order of 2³² key generations (cold gate run 20, M3).",
			},
			stale: []string{
				"| §5.3, §9.4 a held head keeps its acceptance (D-082 (1)) |",
				"applies the same governance entry twice",
				"| §5.1 entry 0 records both seen sets (run 16, L1) |",
				"Step 1's two stated properties are",
				"because a name-only match hands anyone a veto",
				"§13.1's intersection of a peer's allowed-ips with its grant included",
				"but the received-versus-recanonical half cannot be",
			},
		},
		{
			name: "§13.1 the grant bound withholds whole, and overlaps (D-084 (2), (3))",
			from: "### 13.1 Reconciliation modes", to: "### 13.2 Failure semantics",
			want: []string{
				"desired allowed-ips of a peer are the endpoint provider's, each masked, a prefix kept only when one prefix of the peer's grant (§4.0) holds all of it; a provider's prefix wider than the grant, or outside every grant prefix, is withheld whole, never clipped, and reported as a provider claim, so a provider MAY narrow a grant and MUST NOT widen it (D-084 (2)).",
				"Under `\"advisory\"` the provider's prefixes are installed as given, apart from overlaps (below).",
				"**Overlaps (D-081, D-084 (3)).** Under either `routes` value, overlaps are judged on the allowed-ips a node would install, after the grant bound: when a prefix of one proven peer overlaps a prefix of another, neither prefix is installed, each peer keeps its other prefixes, and the pair is reported as a provider claim. WireGuard routes a packet to the peer with the most specific matching prefix, so an overlap would hand one peer's addresses to another, and nothing in the log decided that.",
			},
			stale: []string{"kept only where it lies within a prefix of the peer's grant"},
		},
		{
			name: "§14.1 base64 is not only inside notes (L7)",
			from: "### 14.1 Structure", to: "### 14.2 String escaping",
			want:  []string{"never base64 in this canonical JSON (notes, §7, and `proven.json`, §13.3, carry base64) |"},
			stale: []string{"base64 appears only inside notes"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := section(t, tc.from, tc.to)
			if !tc.exact {
				text = flat(text)
			}
			for _, want := range tc.want {
				if !tc.exact {
					want = flat(want)
				}
				if !strings.Contains(text, want) {
					t.Errorf("SPEC.md must say, in the section from %q:\n%s", tc.from, want)
				}
			}
			for _, stale := range tc.stale {
				if !tc.exact {
					stale = flat(stale)
				}
				if strings.Contains(text, stale) {
					t.Errorf("SPEC.md still says, in the section from %q:\n%s", tc.from, stale)
				}
			}
		})
	}
	t.Run("D-084 is recorded as 1-B, 2-A", func(t *testing.T) {
		decisions := flat(read("DECISIONS.md"))
		start := strings.Index(decisions, "## D-084")
		if start < 0 {
			t.Fatal("DECISIONS.md must record D-084")
		}
		decision := decisions[start+len("## D-084"):]
		if end := strings.Index(decision, "## D-"); end >= 0 {
			decision = decision[:end]
		}
		if !strings.Contains(decision, "**1-B, 2-A**") {
			t.Error("DECISIONS.md D-084 must record **1-B, 2-A**")
		}
		if !strings.Contains(flat(read("HARDENING-PLAN.md")), "D-084 (taken 2026-11-11") {
			t.Error("HARDENING-PLAN.md must list D-084 with its date")
		}
		ledger := read("BUILD-LOG.md")
		if !strings.Contains(ledger, "## DECISION TAKEN — G19:") || strings.Contains(ledger, "## DECISION NEEDED — G19:") {
			t.Error("BUILD-LOG.md must record DECISION TAKEN — G19")
		}
	})
}
