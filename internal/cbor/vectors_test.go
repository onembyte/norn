package cbor

import (
	"encoding/json"
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
