package freshness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/trust"
)

// Cold-model gate run 6, defect H7. `T` decides when a device stops being
// admitted, and its derivation was executed by no vector at all: the served
// checkpoint's three cosignatures carried *identical* timestamps, so the k-th
// newest, the median, the oldest and the newest all agree, and
// `proven/cases.json` supplied `t` directly rather than deriving it from a
// checkpoint. Any defensible reading passed.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func servedQuorumTime(t *testing.T) (int64, int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	anchorRaw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(anchorRaw)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := policy.Parse(doc.Policy)
	if err != nil {
		t.Fatal(err)
	}
	cosignatures, err := cosign.Verify(string(raw), rules.Keys())
	if err != nil {
		t.Fatal(err)
	}
	distinct := map[int64]bool{}
	for _, c := range cosignatures {
		distinct[c.Time.Unix()] = true
	}
	at, ok := QuorumTime(rules, cosignatures)
	if !ok {
		t.Fatal("the served checkpoint has no quorum time")
	}
	return at.Unix(), len(distinct)
}

func TestTheFixturePinsHowTheQuorumTimeIsDerived(t *testing.T) {
	got, distinct := servedQuorumTime(t)
	if distinct < 3 {
		t.Errorf("the served checkpoint's cosignatures carry %d distinct timestamps; with "+
			"fewer than three, the k-th newest, the median and the newest all agree and "+
			"no vector tells them apart", distinct)
	}

	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "proofs", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		CheckpointQuorumTime int64 `json:"checkpoint_quorum_time"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.CheckpointQuorumTime == 0 {
		t.Fatal("the suite records no expected quorum time, so the derivation is still " +
			"executed by nothing")
	}
	if got != doc.CheckpointQuorumTime {
		t.Errorf("quorum time = %d, the suite says %d", got, doc.CheckpointQuorumTime)
	}
}

// `quorum none` requires nobody, so it is satisfied at every instant, not at
// none. A reader applying §5.3's definition literally got an unbounded
// supremum and dropped every expiring device.
func TestQuorumNoneYieldsNoClockRatherThanAnInfiniteOne(t *testing.T) {
	rules, err := policy.Parse("log k\nquorum none\n")
	if err != nil {
		t.Fatal(err)
	}
	if !rules.Satisfied(nil) {
		t.Fatal("`quorum none` should be satisfied by nobody at all; that is the point")
	}
	if _, ok := QuorumTime(rules, nil); ok {
		t.Error("`quorum none` yielded a clock; nobody vouches for the time under it")
	}
}

// Cold-model gate run 7, defect J7. 6.5g-v staggered the fixture's witnesses
// seven seconds apart and claimed in §12.1 that this makes "the newest, the
// median and the k-th newest disagree". With three witnesses and a threshold
// of two, the k-th newest **is** the median. The vector is right and the
// sentence about it was arithmetic nobody did.
func TestTheSpecOnlyClaimsSeparationsTheFixtureMakes(t *testing.T) {
	got, distinct := servedQuorumTime(t)
	if distinct != 3 {
		t.Fatalf("%d distinct cosignature timestamps; this check assumes three", distinct)
	}
	stamps := servedTimestamps(t)
	sort.Slice(stamps, func(i, j int) bool { return stamps[i] > stamps[j] })
	newest, median, oldest := stamps[0], stamps[1], stamps[2]

	if got != median {
		t.Fatalf("quorum time %d is not the middle timestamp %d", got, median)
	}
	// So the fixture separates the k-th newest from the newest and from the
	// oldest, and cannot separate it from the median. The document may claim
	// the first two and must not claim the third.
	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	if median == newest || median == oldest {
		t.Fatal("the timestamps are not distinct enough for this check")
	}
	if strings.Contains(string(spec), "the newest, the median and the k-th newest disagree") {
		t.Error("§12.1 claims the fixture separates the median from the k-th newest. " +
			"With three witnesses and a threshold of two they are the same timestamp, " +
			"and separating them needs a fourth witness")
	}
}

func servedTimestamps(t *testing.T) []int64 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	anchorRaw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(anchorRaw)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := policy.Parse(doc.Policy)
	if err != nil {
		t.Fatal(err)
	}
	cosignatures, err := cosign.Verify(string(raw), rules.Keys())
	if err != nil {
		t.Fatal(err)
	}
	out := make([]int64, 0, len(cosignatures))
	for _, c := range cosignatures {
		out = append(out, c.Time.Unix())
	}
	return out
}

// Cold-model gate run 7, defect J11's other half. §8.1's condition 4 says a
// peer is proven only if its checkpoint "is not stale", and 6.5g-v gave that
// MUST a predicate: `elapsed > params.staleness`. Nothing vectored it. The
// network's `staleness` is carried all the way into `state.json` and was then
// read by no test and no file -- a number shipped to every implementer with
// nothing saying what to do with it.
func TestTheStalenessLadderIsVectored(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "detect", "staleness.json"))
	if err != nil {
		t.Fatalf("the staleness vectors are missing: %v", err)
	}
	var doc struct {
		Staleness int64 `json:"staleness"`
		Hard      int64 `json:"hard"`
		Cases     []struct {
			Name      string `json:"name"`
			Elapsed   int64  `json:"elapsed"`
			HaveClock *bool  `json:"have_clock"`
			Expect    string `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 4 {
		t.Fatalf("%d cases; the ladder has fresh, degraded, hard-stale and no-clock",
			len(doc.Cases))
	}

	limits := Limits{
		Staleness: time.Duration(doc.Staleness) * time.Second,
		Hard:      time.Duration(doc.Hard) * time.Second,
	}
	var sawBoundary bool
	for _, c := range doc.Cases {
		haveClock := true
		if c.HaveClock != nil {
			haveClock = *c.HaveClock
		}
		got := limits.State(time.Duration(c.Elapsed)*time.Second, haveClock)
		if got != c.Expect {
			t.Errorf("%s: elapsed %ds is %q, the suite says %q", c.Name, c.Elapsed, got, c.Expect)
		}
		if c.Elapsed == doc.Staleness && haveClock {
			sawBoundary = true
			if got != Fresh {
				t.Errorf("elapsed exactly equal to `staleness` is %q; the rule is "+
					"`elapsed > staleness`, so the boundary is still fresh", got)
			}
		}
	}
	if !sawBoundary {
		t.Error("no case sits exactly on `staleness`, which is the only value two " +
			"implementations will disagree about")
	}
}
