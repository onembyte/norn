package cbor

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cold-model gate run 5, defect G9. §4.0 states two resource limits as MUSTs
// and then says neither is reachable by a valid entry -- which is true, and is
// why no vector exercised either. Run 5 removed both (`NORN_NOLIMITS`,
// `NORN_NODEPTH`) and passed 597/597. A limit stated and never tested is a
// limit a second implementer may skip, and these two exist precisely for input
// that is not valid.

func TestHostileInputIsRefusedByTheProfile(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "entries-hostile")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatalf("the hostile-input vectors are missing: %v", err)
	}
	var doc struct {
		Cases []struct {
			Name, Says string
			Accepted   bool `json:"accepted"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	// Each limit needs both sides, or it is bounded in one direction only.
	var accepted, refused int
	for _, c := range doc.Cases {
		if c.Accepted {
			accepted++
		} else {
			refused++
		}
	}
	if accepted < 3 || refused < 3 {
		t.Fatalf("%d accepted and %d refused; §4.0's three limits each need a case at "+
			"the limit and a case past it, or a decoder enforcing the wrong value passes",
			accepted, refused)
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(dir, c.Name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			value, err := Decode(body)
			if c.Accepted {
				// The far side of a boundary. Without it the limit is only
				// bounded from one direction, and a decoder enforcing 4 or 64
				// where the profile says 8 passes everything.
				if err != nil {
					t.Fatalf("refused input that sits exactly at the limit: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted hostile input, decoding to %T", value)
			}
			if !strings.Contains(err.Error(), c.Says) {
				t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.Says)
			}
		})
	}
}

// Cold-model gate run 7, defect J1. §4.0 said "the top-level map is depth 1,
// so a value inside it is depth 2" -- which counts scalars -- while both
// implementations count containers, and the vector written for the limit is
// eight nested arrays around a scalar. Under the prose that is depth 9 and
// must be refused; its `cases.json` says accept.
//
// Run 7's `depth-scalars` variant is the only one in seven rounds that failed
// for *following the document*, which is the worst way for a specification to
// be wrong. The rule and the vector are tied together here so neither can move
// without the other.
func TestTheDepthLimitMatchesTheVectorWrittenForIt(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "entries-hostile")
	at, err := os.ReadFile(filepath.Join(dir, "at-the-depth-limit.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	past, err := os.ReadFile(filepath.Join(dir, "past-the-depth-limit.cbor"))
	if err != nil {
		t.Fatal(err)
	}

	// Both vectors are chains of one-element arrays around a scalar, so the
	// number of containers is the number of 0x81 bytes.
	containers := func(raw []byte) int {
		n := 0
		for _, b := range raw {
			if b == 0x81 {
				n++
			}
		}
		return n
	}
	if got := containers(at); got != MaxDepth {
		t.Errorf("the at-the-limit vector nests %d containers and the limit is %d; a "+
			"vector that does not sit exactly on the limit bounds nothing", got, MaxDepth)
	}
	if got := containers(past); got != MaxDepth+1 {
		t.Errorf("the past-the-limit vector nests %d containers, want %d", got, MaxDepth+1)
	}

	// And the document must say which of the two things is counted, because
	// the whole defect was that it said the other one.
	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Markdown wraps and puts emphasis markers mid-phrase; an author should not
	// have to avoid a line break to stay checked (the same correction 6.3 made
	// to the README checks).
	flat := strings.Join(strings.Fields(strings.ReplaceAll(string(spec), "*", "")), " ")
	if !strings.Contains(flat, "A scalar does not add depth") {
		t.Error("§4.0 does not say whether a scalar adds depth. It counted values once, " +
			"the implementations count containers, and the vector followed the " +
			"implementations")
	}
}

// Cold-model gate run 7, defect J12. §4.0 caps every map key at 1-23 bytes, and
// the only vector for it was `requests-bad/oversize-label-key` -- which the
// `labels` *field* rule refuses first, so the decoder-level cap was
// unobservable and `no-key-cap` passed. §12.1 half-admitted this and listed
// the rule as covered anyway.
//
// The cap belongs with the other two resource limits, whose vectors are raw
// bytes for the same reason: an encoder that enforces the profile cannot
// produce the hostile case.
func TestTheKeyLimitVectorsSitExactlyOnTheCap(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "entries-hostile")
	keyLen := func(name string) int {
		raw, err := os.ReadFile(filepath.Join(dir, name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		// Each vector is a one-pair map whose key is a definite-length text
		// string: 0xa1, then 0x60|n for n < 24, else 0x78 and one length byte.
		if len(raw) < 3 || raw[0] != 0xa1 {
			t.Fatalf("%s is not a one-pair map", name)
		}
		switch {
		case raw[1] >= 0x60 && raw[1] < 0x78:
			return int(raw[1] - 0x60)
		case raw[1] == 0x78:
			return int(raw[2])
		}
		t.Fatalf("%s does not begin with a definite-length text key", name)
		return 0
	}
	if got := keyLen("at-the-key-limit"); got != MaxKeyLen {
		t.Errorf("the at-the-limit key is %d bytes and the cap is %d; a vector that "+
			"does not sit on the limit bounds nothing", got, MaxKeyLen)
	}
	if got := keyLen("past-the-key-limit"); got != MaxKeyLen+1 {
		t.Errorf("the past-the-limit key is %d bytes, want %d", got, MaxKeyLen+1)
	}
}

// --- Cold-model gate run 8, defect D15 ----------------------------------
//
// §4.0 bans floats, tags, null, undefined, negative integers, indefinite
// lengths and non-text map keys. The suite had a negative for each **as part
// of an entry** -- and every one of them is refused by a *later* rule too, so
// `cbor-allow-null`, `cbor-allow-negative` and `cbor-allow-nontext-mapkey`
// each reproduced the whole manifest.
//
// `65-bad-cbor-null` shows why: the null replaces `after`'s value, so a
// lenient decoder hands the envelope check a non-uint `after` and the entry is
// `decode` either way. The reason code is the same, so `manifest.json` cannot
// tell the two readings apart. Confirmed by mutation: allowing null leaves
// every replay vector green.
//
// The profile is a property of the *decoder*, so it belongs where the other
// decoder-level rules already live -- fed to a bare reader with no schema
// above it to intervene first.

func TestEveryForbiddenProfileItemHasADecoderCase(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "entries-hostile")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name, Says string
			Accepted   bool `json:"accepted"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, c := range doc.Cases {
		have[c.Name] = true
	}
	// One per banned item, by the name §4.0 uses for it.
	for _, want := range []string{
		"bare-null", "bare-undefined", "bare-float", "bare-negative-integer",
		"bare-tag", "bare-indefinite-text", "bare-nontext-map-key",
		"bare-invalid-utf8", "bare-simple",
	} {
		if !have[want] {
			t.Errorf("§4.0 bans this and `entries-hostile/%s` does not ship, so the "+
				"rule is reachable only through an entry -- where a later rule "+
				"refuses it first and the reason code is the same either way", want)
		}
		raw, err := os.ReadFile(filepath.Join(dir, want+".cbor"))
		if err != nil {
			t.Error(err)
			continue
		}
		if _, err := Decode(raw); !errors.Is(err, ErrProfile) {
			t.Errorf("%s: want profile refusal, got %v", want, err)
		}
	}
}

// --- Cold-model gate run 10, defects D7 and D8 --------------------------
//
// Both are readings a second implementer could hold while passing the whole
// suite, and both are about a rule the table states *twice over* in one place
// and *not at all* in another.

// logVector reads one entry of the replay fixture by the tail of its name. The
// numbers shift whenever a vector is inserted earlier in the log, so nothing
// here may index by one.
func logVector(t *testing.T, suffix string) []byte {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "vectors", "log")
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries []struct{ Name string } `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, e := range doc.Entries {
		if strings.HasSuffix(e.Name, suffix) {
			body, err := os.ReadFile(filepath.Join(dir, e.Name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
	t.Fatalf("no log entry named *%s", suffix)
	return nil
}

// widenTheBodyText returns the control with its body text's length header
// re-encoded one byte wider: `0x6D` becomes `0x78 0x0D`. Same string, same
// value, an encoding RFC 8949 §4.2.1 does not permit.
func widenTheBodyText(control []byte) []byte {
	value := []byte("profile probe")
	definite := append([]byte{0x60 | byte(len(value))}, value...)
	at := bytes.Index(control, definite)
	if at < 0 {
		return nil
	}
	out := append([]byte{}, control[:at]...)
	out = append(out, 0x78, byte(len(value)))
	out = append(out, value...)
	return append(out, control[at+len(definite):]...)
}

// D7. §4.0 put "shortest form" in the **Integers** row, and the one vector for
// it patches an integer, so a reader who applies the rule to integers and to
// nothing else passes every check in the suite. Under that reading one logical
// entry has several legal encodings; `entry_hash` is over the bytes as
// received, so two encodings of one governance entry are two distinct leaves
// that both replay -- walking around the `dup-entry` defence by exactly the
// route §4.1's consume-the-whole-input rule exists to close.
func TestTheShortestFormRuleIsVectoredOnALengthHeaderToo(t *testing.T) {
	control := logVector(t, "-profile-base")
	patched := logVector(t, "-bad-cbor-nonshortest-length")

	if _, err := Decode(control); err != nil {
		t.Fatalf("the control entry does not decode: %v", err)
	}
	_, err := Decode(patched)
	if err == nil {
		t.Fatal("a widened length header was accepted; shortest form is required of " +
			"every argument, not only of integers")
	}
	if !strings.Contains(err.Error(), "non-shortest") {
		t.Errorf("refused as %q, which is not the rule this vector is about", err)
	}
	// And nothing else is wrong with it: the vector is the control with one
	// text-string header widened, so a reader that refuses it refuses it for
	// the header or for nothing.
	if want := widenTheBodyText(control); !bytes.Equal(want, patched) {
		t.Error("the shipped vector is not the control with its body text header " +
			"widened, so something other than the length header may be refusing it")
	}
}

// D8. "keys sorted as §4.1" and "no duplicate keys" were stated as two rules,
// and §4.1 never said *strictly* increasing. Each rule hid the gap in the
// other: a reader with no duplicate test still refuses the one duplicate
// vector, because equal keys are not increasing; a reader who reads "sorted"
// as non-decreasing still refuses it, because of the duplicate test. Drop both
// -- non-decreasing order and last-key-wins, which is what a lenient CBOR
// decoder does by default -- and the duplicated key is accepted. One
// comparison is the whole rule, and the document now says so.
func TestEqualKeysAreRefusedByTheOrderingComparisonItself(t *testing.T) {
	_, duplicate := Decode(logVector(t, "-bad-duplicate-map-key"))
	_, unsorted := Decode(logVector(t, "-bad-cbor-unsorted-keys"))
	if duplicate == nil || unsorted == nil {
		t.Fatalf("both must be refused; got %v and %v", duplicate, unsorted)
	}
	if duplicate.Error() != unsorted.Error() {
		t.Errorf("a duplicate key is refused as %q and an out-of-order key as %q; two "+
			"messages are two rules, and a reader can implement one and miss the other",
			duplicate, unsorted)
	}
}

// A bare item has no schema, signature or field constraint to hide a missing
// profile ban. D-074 (h) makes this simple value an explicit forbidden item.
func TestBareSimpleValueIsRefusedOnlyByTheProfile(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "entries-hostile")
	raw, err := os.ReadFile(filepath.Join(dir, "bare-simple.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte{0xf0}) {
		t.Fatalf("bare-simple is %x, want the simple value 16 alone", raw)
	}
	if _, err := Decode(raw); !errors.Is(err, ErrProfile) || !strings.Contains(err.Error(), "simple value 16") {
		t.Fatalf("want simple value 16 profile refusal, got %v", err)
	}
	if value, err := Decode([]byte{0xf5}); err != nil || value != true {
		t.Fatalf("true is a permitted profile item: %v, %v", value, err)
	}
}
