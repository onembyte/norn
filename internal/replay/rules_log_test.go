package replay

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/entry"
)

// These outcomes are the rules in §4.0, §4.3, §4.4 and §5.1, independent of
// the manifest. The repairs retain the original content wherever possible.
func TestEveryRuleCaseMatchesAndEachRefusalRepairs(t *testing.T) {
	names := []string{"00-genesis", "01-enroll-nas", "02-enroll-laptop", "03-revoke-nas-by-laptop", "04-revoke-nas-by-self", "05-signer-add-without-prev", "06-signer-add-prev-zero", "07-note-without-ts", "08-note-with-ts", "09-enroll-empty-label-value", "10-policy-preannounces-log-key", "11-log-key-preannounced", "12-copy-enroll-unsorted-sigs", "13-copy-enroll-sorted-sigs", "14-root-threshold-full", "15-root-remove-unknown-before-invariant", "16-root-remove-known-at-full-threshold", "17-root-threshold-repaired", "18-root-remove-known"}
	codes := []string{"", "", "", ReasonThreshold, "", ReasonStaleState, "", ReasonDecode, "", "", "", "", ReasonDecode, ReasonDupEntry, "", ReasonUnknownKey, ReasonRootInvariant, "", ""}
	dir := vectorRoot() + "/log-rules"
	anchor, raw, m := loadCase(t, dir)
	if len(raw) != len(names) {
		t.Fatalf("got %d entries, want %d", len(raw), len(names))
	}
	read := func(path string) []byte {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var metadata struct {
		Anchor map[string]string
		Codes  map[string]string
		Rules  map[string]struct{ Section, Says string }
	}
	if err := json.Unmarshal(read(dir+"/manifest.json"), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Anchor) != 4 || len(metadata.Rules) != len(names) {
		t.Fatal("anchor or rules incomplete")
	}
	spec := string(read("../../SPEC.md"))
	final := Replay(anchor, raw)
	refusals := 0
	for i, name := range names {
		t.Run(name, func(t *testing.T) {
			if m.Entries[i].Name != name || m.Entries[i].Index != i || m.Entries[i].Reason != codes[i] {
				t.Fatal("manifest differs from stated answer")
			}
			rule, ok := metadata.Rules[name]
			heading := "## "
			if strings.Contains(rule.Section, ".") {
				heading = "### "
			}
			_, section, found := strings.Cut(spec, heading+rule.Section+" ")
			section, _, _ = strings.Cut(section, "\n##")
			onLine := false
			for _, line := range strings.Split(section, "\n") {
				onLine = onLine || strings.Contains(line, rule.Says)
			}
			if !ok || !found || rule.Says == "" || !onLine {
				t.Fatal("rule does not cite one raw normative line")
			}
			if got := lastOutcome(final, i); got != codes[i] {
				t.Fatalf("Go = %q, want %q", got, codes[i])
			}
			t.Logf("Go = %q", codes[i])
			if codes[i] == "" {
				return
			}
			refusals++
			if metadata.Codes[name] != codes[i] || string(read(dir+"/"+name+".reason")) != codes[i]+"\n" {
				t.Fatal("code or reason differs")
			}
			before, after := Replay(anchor, raw[:i]), Replay(anchor, raw[:i+1])
			after.Size, after.Rejected = before.Size, before.Rejected
			a, err := after.MarshalCanonical()
			if err != nil {
				t.Fatal(err)
			}
			b, err := before.MarshalCanonical()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Fatal("refusal changed state")
			}
			check := func(prefix [][]byte, value []byte, want string) {
				t.Helper()
				result := Replay(anchor, append(append([][]byte(nil), prefix...), value))
				if got := lastOutcome(result, len(prefix)); got != want {
					t.Fatalf("repair Go = %q, want %q", got, want)
				}
			}
			value, err := cbor.Decode(raw[i])
			if err != nil {
				t.Fatal(err)
			}
			env := value.(map[string]any)
			sign := func(keys []string, role string) []byte {
				t.Helper()
				env["sigs"] = []any{}
				encoded, err := cbor.Encode(env)
				if err != nil {
					t.Fatal(err)
				}
				e, err := entry.Decode(encoded)
				if err != nil {
					t.Fatal(err)
				}
				for _, key := range keys {
					if err := entry.Sign(e, privateKey(t, key), role); err != nil {
						t.Fatal(err)
					}
				}
				encoded, err = entry.Encode(e)
				if err != nil {
					t.Fatal(err)
				}
				return encoded
			}
			paired := func(value []byte, index int) {
				t.Helper()
				if !bytes.Equal(value, raw[index]) {
					t.Fatal("repair changes more than its named fault")
				}
			}
			switch i {
			case 3:
				paired(sign([]string{"nas"}, "device"), 4)
				check(raw[:i], raw[4], "")
			case 5:
				if _, ok := env["prev"]; ok {
					t.Fatal("prev should be absent")
				}
				env["prev"] = uint64(0)
				paired(sign([]string{"root1", "root2"}, "root"), 6)
				check(raw[:i], raw[6], "")
			case 7:
				if _, ok := env["ts"]; ok {
					t.Fatal("ts should be absent")
				}
				value, err := cbor.Decode(raw[8])
				if err != nil {
					t.Fatal(err)
				}
				env["ts"] = value.(map[string]any)["ts"]
				paired(sign([]string{"signer1"}, "signer"), 8)
				check(raw[:i], raw[8], "")
			case 12:
				sigs := env["sigs"].([]any)
				if len(sigs) != 2 {
					t.Fatal("copy needs two signatures")
				}
				sigs[0], sigs[1] = sigs[1], sigs[0]
				encoded, err := cbor.Encode(env)
				if err != nil {
					t.Fatal(err)
				}
				paired(encoded, 1)
				paired(raw[13], 1)
				check(raw[:i], raw[13], ReasonDupEntry)
				check(raw[:1], raw[13], "")
			case 13:
				check(raw[:1], raw[i], "")
			case 15:
				env["body"].(map[string]any)["kid"] = entry.Kid(publicOf(t, "root3"))
				paired(sign([]string{"root1", "root2", "root3"}, "root"), 16)
				check(raw[:i], raw[16], ReasonRootInvariant)
				check(raw[:18], raw[18], "")
			case 16:
				check(raw[:18], raw[18], "")
			default:
				t.Fatal("refusal has no repair")
			}
		})
	}
	if len(metadata.Codes) != refusals {
		t.Fatal("codes has extra or missing refusals")
	}
	got, err := final.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, read(dir+"/state.json")) {
		t.Fatal("rule state differs from state.json")
	}
}
