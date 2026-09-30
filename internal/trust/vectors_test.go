package trust

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
)

// --- Cold-model gate run 10, defect D12 ---------------------------------
//
// Three §9.1 MUSTs about the log key, each deletable from this implementation
// with no vector noticing. `V90` (drop "`origin` is `norn/` + base32(`net`)"),
// `V93` (drop "the log key's note name equals `origin`") and `V92` (drop
// "`log_key` MUST NOT be a cosignature key") each passed all 236 checks.
//
// The cause is the same in all three: the negative damages `log_key` or
// `origin` and leaves the **policy** carrying the original key, so §9.1's
// correspondence rule — a `log` line, if present, MUST be `norn.trust.log_key`
// — refuses the file before the rule the case is named after is reached. Run
// 10 called `V90`/`V93` the sharpest pair: two separate MUSTs, each with no
// observable effect, and only deleting *both* lets a file through.
//
// A negative is about the rule it names or it is about nothing, so each of
// these carries its damaged key in its policy too.

func trustBad(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"trust-bad", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	// Decoded, not parsed: `Parse` is what these files exist to fail.
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatalf("%s does not even decode, so it cannot be about a §9.1 rule: %v",
			name, err)
	}
	doc, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is not a map", name)
	}
	return doc
}

func TestTheLogKeyNegativesDoNotAlsoBreakTheCorrespondenceRule(t *testing.T) {
	for _, suffix := range []string{
		"log-key-name-mismatch",
		"origin-only",
		"log-key-is-a-cosignature-key",
		// Cold gate run 11, D3: the fourth, and the one 6.5k-v-a missed.
		"log-key-id-mismatch",
		// D7: the note name and the origin, each moved as little as it can be.
		"log-key-name-with-a-suffix",
		"log-key-name-in-upper-case",
		"log-key-name-truncated",
		"origin-in-upper-case",
		"origin-non-canonical-padding-bits",
	} {
		// By suffix: the numeric prefix moves as cases are inserted, and a
		// list keyed on numbers silently stops checking what it names.
		name := isolated(t, suffix)
		t.Run(name, func(t *testing.T) {
			doc := trustBad(t, name)
			logKey, _ := doc["log_key"].(string)
			text, _ := doc["policy"].(string)
			if logKey == "" || text == "" {
				t.Fatalf("the case carries log_key=%q and a %d-byte policy", logKey, len(text))
			}
			var found bool
			for _, line := range strings.Split(text, "\n") {
				fields := strings.Fields(line)
				if len(fields) < 2 || fields[0] != "log" {
					continue
				}
				found = true
				if fields[1] != logKey {
					t.Errorf("the policy's log line names\n  %s\nand `log_key` is\n  %s\n"+
						"so §9.1's correspondence rule refuses this file and the rule it "+
						"is named after is never reached", fields[1], logKey)
				}
			}
			if !found {
				t.Error("the policy carries no `log` line, so the correspondence rule " +
					"is vacuous here and the case says less than it could")
			}
			// It must still be refused, of course.
			raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
				"trust-bad", name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			doc2, err := Parse(raw)
			if err == nil {
				err = doc2.Validate()
			}
			if err == nil {
				t.Error("the file must be refused")
			}
		})
	}
}

// Cold-model gate run 11, D7. `11` names the log key `someone/else` and `13`
// derives nothing like this network's origin, so a prefix match and a
// case-folded one refuse them as readily as `==` does, and a decoder that
// ignores padding bits never meets a spelling it would forgive. Each of these
// moves one string as little as it can be moved. The shape is asserted before
// the verdict: the key is this log's note key, and the one string is exactly
// the variant the case is named for.
func TestTheOriginSpellingNegativesMoveOneThing(t *testing.T) {
	good := loadGood(t)
	honestKey, err := parseKey(good.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		suffix string
		// shape reports what is wrong with a case, given its origin, the
		// honest origin its net derives, and its log key's note name.
		shape func(origin, honest, name string, net []byte) string
	}{
		{"log-key-name-with-a-suffix", func(origin, honest, name string, _ []byte) string {
			if origin != honest || len(name) != len(origin)+1 || !strings.HasPrefix(name, origin) {
				return "the note name is not `origin` plus one character"
			}
			return ""
		}},
		{"log-key-name-in-upper-case", func(origin, honest, name string, _ []byte) string {
			if origin != honest || name == origin || !strings.EqualFold(name, origin) {
				return "the note name is not `origin` in another case"
			}
			return ""
		}},
		{"log-key-name-truncated", func(origin, honest, name string, _ []byte) string {
			if origin != honest || len(name)+1 != len(origin) || !strings.HasPrefix(origin, name) {
				return "the note name is not `origin` less one character"
			}
			return ""
		}},
		{"origin-in-upper-case", func(origin, honest, name string, _ []byte) string {
			if name != origin || origin == honest || !strings.EqualFold(origin, honest) {
				return "`origin` is not the derived origin in another case, with the key named for it"
			}
			return ""
		}},
		{"origin-non-canonical-padding-bits", func(origin, honest, name string, net []byte) string {
			if name != origin || origin == honest || len(origin) != len(honest) ||
				origin[:len(origin)-1] != honest[:len(honest)-1] {
				return "`origin` is not the derived origin with only its last character changed"
			}
			// The lax reading, run for real: this repository's own input
			// parser decodes it, folding case and ignoring the padding bits,
			// and gets this network's net back.
			back, err := NetFromOrigin(origin)
			if err != nil || !bytes.Equal(back, net) {
				return "a decoder does not map this origin to the same net, so it " +
					"separates nothing"
			}
			return ""
		}},
	} {
		name := isolated(t, c.suffix)
		t.Run(name, func(t *testing.T) {
			doc := trustBad(t, name)
			origin, _ := doc["origin"].(string)
			net := mustBytes(t, doc["net"])
			honest, err := OriginFor(net)
			if err != nil {
				t.Fatal(err)
			}
			logKey, _ := doc["log_key"].(string)
			parsed, err := parseKey(logKey)
			if err != nil {
				t.Fatalf("the log key must parse, id and all, or another rule refuses "+
					"it: %v", err)
			}
			if parsed.IsCosigner() || !bytes.Equal(parsed.Public, honestKey.Public) {
				t.Fatalf("the key is not this log's note key under another name")
			}
			if problem := c.shape(origin, honest, parsed.Name, net); problem != "" {
				t.Fatalf("%s: origin %q, derived %q, note name %q", problem, origin,
					honest, parsed.Name)
			}
			raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust-bad", name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			doc2, err := Parse(raw)
			if err == nil {
				err = doc2.Validate()
			}
			if err == nil {
				t.Error("the file must be refused")
			}
		})
	}
}

func mustBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, ok := v.([]byte)
	if !ok {
		t.Fatalf("not a byte string: %T", v)
	}
	return b
}
