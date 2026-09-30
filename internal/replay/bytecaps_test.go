package replay

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/policy"
)

// --- Cold-model gate run 11, defect D6 ----------------------------------
//
// §4.0's caps are bytes of UTF-8. Every over-long vector was ASCII, so a
// reader that counted characters passed the suite; no text sat at a cap, so a
// reader that refused one did too; and no `policy` was over its cap at all.
// Each cap now ships as a pair: a positive at exactly the cap, and a negative
// that is the same value with one ASCII letter replaced by a two-byte one.

// sameCharactersOneByteOver is the construction every pair shares. The
// negative is one byte over; under code points and UTF-16 code units the two
// are the same length, so a reader counting either accepts both or neither.
func sameCharactersOneByteOver(t *testing.T, pos, neg string, cap int) {
	t.Helper()
	if len(pos) != cap || len(neg) != cap+1 {
		t.Fatalf("%d and %d bytes; the pair must sit at %d and one past it", len(pos), len(neg), cap)
	}
	p, n := []rune(pos), []rune(neg)
	if len(p) != len(n) || len(utf16.Encode(p)) != len(utf16.Encode(n)) {
		t.Fatalf("the two differ in characters (%d and %d code points, %d and %d UTF-16 "+
			"units), so a reader counting characters can tell them apart",
			len(p), len(n), len(utf16.Encode(p)), len(utf16.Encode(n)))
	}
	var differ int
	for i := range p {
		if p[i] != n[i] {
			differ++
			if utf8.RuneLen(p[i]) != 1 || utf8.RuneLen(n[i]) != 2 {
				t.Errorf("character %d is %q in the positive and %q in the negative; "+
					"the swap is one ASCII letter for one two-byte letter", i, p[i], n[i])
			}
		}
	}
	if differ != 1 {
		t.Fatalf("%d characters differ; the pair must differ in exactly one", differ)
	}
	// Every UTF-8 width, so bytes, code points and UTF-16 units are three
	// different numbers, and a four-byte character is six in modified UTF-8.
	widths := map[int]int{}
	for _, r := range p {
		widths[utf8.RuneLen(r)]++
	}
	for w := 1; w <= 4; w++ {
		if widths[w] == 0 {
			t.Errorf("the positive has no %d-byte character", w)
		}
	}
	// More ASCII than three-byte characters: two bytes per UTF-16 unit is
	// then over the cap, so a reader counting UTF-16 bytes refuses the positive.
	if 2*len(utf16.Encode(p)) <= cap {
		t.Errorf("the positive is %d bytes in UTF-16, within the cap of %d", 2*len(utf16.Encode(p)), cap)
	}
	// Measured as encoded (§4.0): a reader that normalises first finds the
	// positive over its cap, because the motif holds a letter that decomposes.
	if n := nfdLen(pos); n <= cap {
		t.Errorf("the positive is %d bytes under NFD, within the cap of %d", n, cap)
	}
}

// nfdLen is the UTF-8 length of `s` under NFD, for text whose only
// decomposable character is U+00E9: `é` is two bytes as sent and three (`e`
// U+0301) once decomposed. Computed here rather than with x/text, which this
// module does not depend on.
func nfdLen(s string) int {
	return len(s) + strings.Count(s, "\u00e9")
}

// directives is a policy with its comment lines removed.
func directives(text string) string {
	var keep []string
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

// exactName finds the entry whose name, after its index, is exactly this.
func exactName(t *testing.T, m manifest, want string) (int, string, string) {
	t.Helper()
	for i, e := range m.Entries {
		if _, rest, ok := strings.Cut(e.Name, "-"); ok && rest == want {
			return i, e.Name, e.Reason
		}
	}
	t.Fatalf("the fixture has no entry named %q", want)
	return 0, "", ""
}

func TestTheLogsTextCapsCountBytesNotCharacters(t *testing.T) {
	anchor, entries, m := loadCase(t, filepath.Join(vectorRoot(), "log"))
	r := &replayer{verify: realVerify}
	// The verdicts come from replaying, not from the manifest: a test that
	// read `reason` from `manifest.json` could not go red under a lax reader.
	refused := map[uint64]string{}
	for _, rj := range Replay(anchor, entries).Rejected {
		refused[rj.Index] = rj.Reason
	}
	for _, c := range []struct {
		pos, neg, field string
		cap             int
	}{
		{"revoke-by-roots", "bad-revoke-reason-too-long", "reason", 256},
		{"note", "bad-text-too-long", "text", 4096},
		{"policy-rotated", "bad-policy-text-too-long", "text", 4096},
	} {
		t.Run(c.neg, func(t *testing.T) {
			posIndex, posName, _ := exactName(t, m, c.pos)
			index, negName, _ := exactName(t, m, c.neg)
			pos := envNamed(t, m, posName)
			neg := envNamed(t, m, negName)
			if pos.T != neg.T {
				t.Fatalf("a %s and a %s: the pair must be one entry type", pos.T, neg.T)
			}
			posText, _ := pos.Body[c.field].(string)
			negText, _ := neg.Body[c.field].(string)
			sameCharactersOneByteOver(t, posText, negText, c.cap)

			// Nothing but the cap stands between the negative and acceptance.
			before := Replay(anchor, entries[:index])
			switch neg.T {
			case "revoke":
				id, _ := neg.Body["device_id"].(string)
				if d, ok := before.Devices[id]; !ok || d.Status != "active" {
					t.Fatalf("%s is not active before the entry, so another rule refuses it", id)
				}
				if r.countRole(before, neg, "root") < before.RootThr {
					t.Fatal("the negative is short of a root quorum, so `threshold` could refuse it")
				}
			case "note":
				if r.countRole(before, neg, "signer")+r.countRole(before, neg, "root") == 0 {
					t.Fatal("the negative has no valid signer or root, so `threshold` could refuse it")
				}
			case "policy":
				if r.countRole(before, neg, "root") < before.RootThr {
					t.Fatal("the negative is short of a root quorum, so `threshold` could refuse it")
				}
				if _, err := policy.Parse(negText); err != nil {
					t.Fatalf("the negative is not a policy, so the parse rule could refuse it: %v", err)
				}
				// The extra byte is in the comment: every directive is the
				// positive's, so the negative means exactly what it means.
				if directives(negText) != directives(posText) {
					t.Error("the two policies differ outside their comments")
				}
			}
			if len(neg.Body) != len(pos.Body) {
				t.Errorf("the bodies carry %d and %d keys", len(pos.Body), len(neg.Body))
			}

			// Then the verdicts.
			if reason, ok := refused[uint64(posIndex)]; ok {
				t.Errorf("%s is refused %q; it sits exactly at the cap and MUST be accepted", posName, reason)
			}
			if refused[uint64(index)] != ReasonDecode {
				t.Errorf("%s is refused %q, want decode", negName, refused[uint64(index)])
			}
		})
	}
}

func genesisBody(t *testing.T, path string) (map[string]any, *entry.Envelope) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)["body"].(map[string]any), env
}

// genesis/14 and genesis-good/name-at-the-cap are the same genesis but for
// its name: the same body otherwise, and root signatures that meet the
// threshold the body sets, so only the name bound can abort one of them.
func TestTheGenesisNameCapCountsBytesNotCharacters(t *testing.T) {
	posBody, posEnv := genesisBody(t, filepath.Join(vectorRoot(), "genesis-good", "name-at-the-cap", "00-genesis.cbor"))
	negBody, negEnv := genesisBody(t, filepath.Join(vectorRoot(), "genesis", "14-name-too-long", "00-genesis.cbor"))
	posName, _ := posBody["name"].(string)
	negName, _ := negBody["name"].(string)
	sameCharactersOneByteOver(t, posName, negName, 64)

	for _, b := range []map[string]any{posBody, negBody} {
		delete(b, "name")
	}
	if !reflect.DeepEqual(posBody, negBody) {
		t.Error("the two bodies differ in more than `name`")
	}
	for _, env := range []*entry.Envelope{posEnv, negEnv} {
		roots, _ := env.Body["roots"].([]any)
		thr, _ := env.Body["root_thr"].(uint64)
		var valid uint64
		for _, sig := range env.Sigs {
			for _, r := range roots {
				pk, _ := r.([]byte)
				if sig.Role != "root" || sig.Kid != entry.Kid(pk) {
					continue
				}
				if ok, err := entry.Verify(env, sig, pk); err == nil && ok {
					valid++
				}
			}
		}
		if thr == 0 || valid < thr {
			t.Errorf("%d valid bootstrap signatures of %d: step 7 could abort it", valid, thr)
		}
	}

	// Then the verdicts, from the shipped manifests.
	for dir, want := range map[string]string{
		filepath.Join("genesis-good", "name-at-the-cap"): "",
		filepath.Join("genesis", "14-name-too-long"):     ReasonBadGenesis,
	} {
		anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), dir))
		st := Replay(anchor, entries)
		got := ""
		if len(st.Rejected) > 0 {
			got = st.Rejected[0].Reason
		}
		if got != want {
			t.Errorf("%s: refused %q, want %q", dir, got, want)
		}
	}
}

// `genesis/` holds only aborts; `genesis-good/` is the other side, and a
// reader that refuses one of these rejects a network this document accepts.
func TestEveryGenesisGoodCaseIsAccepted(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "genesis-good", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []string `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("genesis-good lists no cases")
	}
	for _, name := range doc.Cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(vectorRoot(), "genesis-good", name)
			anchor, entries, _ := loadCase(t, dir)
			st := Replay(anchor, entries)
			if len(st.Rejected) != 0 || st.Size != 1 {
				t.Fatalf("refused %+v; this genesis MUST be accepted", st.Rejected)
			}
			got, err := st.MarshalCanonical()
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(dir, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Error("the state differs from its state.json")
			}
		})
	}
}
