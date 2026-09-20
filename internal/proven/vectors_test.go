package proven

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Cold-model gate run 5, defect G5. `expires` is the rule that decides when a
// device stops being admitted to the VPN, and it was the least tested thing in
// the suite: `state.json` is deliberately clock-independent, so nothing in
// 294 files exercised expiry at all. The prose said two different things about
// which clock to use (6.5a settled that), and the boundary -- whether a device
// whose `expires` equals the evaluation time is in or out -- was pinned only
// by a Go unit test, which is exactly the evidence a second implementer does
// not receive.

type provenCase struct {
	Name   string   `json:"name"`
	T      int64    `json:"t"`
	Proven []string `json:"proven"`
	Why    string   `json:"why"`
}

func provenCases(t *testing.T) []provenCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "proven", "cases.json"))
	if err != nil {
		t.Fatalf("the proven-set fixture is missing: %v", err)
	}
	var doc struct {
		Cases []provenCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

func TestTheProvenSetFixture(t *testing.T) {
	result, _ := verified(t)
	cases := provenCases(t)
	if len(cases) < 4 {
		t.Fatalf("%d cases; the fixture must cover no clock, before, at and after the deadline",
			len(cases))
	}

	var sawBoundary, sawNoClock bool
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			// t = 0 means no clock at all: no quorum of witnesses vouches for
			// any instant, so §5.3 says expiry is not judged.
			at := time.Time{}
			if c.T != 0 {
				at = time.Unix(c.T, 0)
			}
			got := Devices(result.State, at)
			if strings.Join(got, ",") != strings.Join(c.Proven, ",") {
				t.Errorf("proven set at T=%d:\n  got  %v\n  want %v", c.T, got, c.Proven)
			}
		})
		if c.T == 0 {
			sawNoClock = true
		}
	}

	// The case that separates `<` from `<=`, and the one nobody writes twice.
	for _, c := range cases {
		if c.Name == "at-the-deadline" {
			sawBoundary = true
			for _, id := range c.Proven {
				if id == "contractor" {
					t.Error("a device whose expires equals T is still proven; §5.3 says " +
						"`expires <= T` has passed")
				}
			}
		}
	}
	if !sawBoundary {
		t.Error("no case sits exactly on the deadline, which is the only value two " +
			"implementations will disagree about")
	}
	if !sawNoClock {
		t.Error("no case has T = 0; a node with no witness quorum has no clock and must " +
			"not drop devices on a number nobody signed")
	}
}

// What the `no-clock` case is actually for.
//
// It cannot be made to discriminate against *this* implementation: Norn
// represents "no clock" as the zero time, whose Unix seconds are more negative
// than any `expires` a uint64 can hold, so removing the explicit zero check
// changes no answer. No fixture can catch that, and pretending otherwise would
// be the same self-congratulation this suite keeps finding.
//
// It discriminates against the implementation a second implementer is most
// likely to write: one that, finding no witness quorum, quietly falls back to
// the machine's own clock. That is precisely what A11 forbids, and the
// fixture's deadline is in the past, so such a verifier drops a device the
// fixture says is proven.
func TestTheNoClockCaseCatchesAWallClockFallback(t *testing.T) {
	result, _ := verified(t)

	var noClock []string
	for _, c := range provenCases(t) {
		if c.T == 0 {
			noClock = c.Proven
		}
	}
	if noClock == nil {
		t.Fatal("there is no no-clock case")
	}

	wallClock := Devices(result.State, time.Now())
	if strings.Join(wallClock, ",") == strings.Join(noClock, ",") {
		t.Error("a verifier that substituted its own clock would produce the same answer, " +
			"so the fixture no longer catches the fallback A11 forbids -- the deadline it " +
			"turns on has stopped being in the past")
	}
}
