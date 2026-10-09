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
	anchorRaw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := trust.Parse(anchorRaw)
	if err != nil {
		t.Fatal(err)
	}
	policyText := strings.SplitN(anchor.Policy, "quorum ", 2)[0] + "quorum none\n"
	rules, err := policy.Parse(policyText)
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
			Hard      *int64 `json:"hard"`
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

	var sawBoundary bool
	for _, c := range doc.Cases {
		// A case may carry its own `hard`, overriding the table's (D9).
		hard := doc.Hard
		if c.Hard != nil {
			hard = *c.Hard
		}
		limits := Limits{
			Staleness: time.Duration(doc.Staleness) * time.Second,
			Hard:      time.Duration(hard) * time.Second,
		}
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

// Cold-model gate run 9, defect D9. §8.1 makes `S_hard` opt-in and says why:
// crossing it drops **every peer**, so a node never configured for one stays
// `degraded` for ever rather than taking a network down because a log was
// unreachable over a weekend. All five cases carried `hard: 3600`, so
// `hard-stale-when-zero` -- which treats 0 as "no headroom" instead of "not
// configured" -- passed the whole suite, and that reading does exactly what
// the asymmetry exists to prevent.
func TestTheUnconfiguredHardLimitIsVectored(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "detect", "staleness.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Staleness int64 `json:"staleness"`
		Hard      int64 `json:"hard"`
		Cases     []struct {
			Name      string `json:"name"`
			Elapsed   int64  `json:"elapsed"`
			Hard      *int64 `json:"hard"`
			HaveClock *bool  `json:"have_clock"`
			Expect    string `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	var unconfigured int
	for _, c := range doc.Cases {
		hard := doc.Hard
		if c.Hard != nil {
			hard = *c.Hard
		}
		if hard == 0 {
			unconfigured++
		}
		clock := true
		if c.HaveClock != nil {
			clock = *c.HaveClock
		}
		limits := Limits{
			Staleness: time.Duration(doc.Staleness) * time.Second,
			Hard:      time.Duration(hard) * time.Second,
		}
		got := limits.State(time.Duration(c.Elapsed)*time.Second, clock)
		if got != c.Expect {
			t.Errorf("%s: state %q, want %q", c.Name, got, c.Expect)
		}
	}
	if unconfigured == 0 {
		t.Error("no case carries `hard: 0`, so a reader that treats an unconfigured " +
			"S_hard as no headroom -- dropping every peer -- passes the whole suite")
	}
}

// --- Cold-model gate run 11, defect D1 (D-060) --------------------------
//
// §8.1's four states were a table with no stated evaluation order, and
// `fresh` and `hard_stale` are both true whenever `S_hard < elapsed ≤ S`. The
// implementation tested `fresh` first, which made a node's own hard limit
// unreachable whenever the network's `staleness` was at or above it — and
// `staleness` moves by root quorum, so a root quorum could silently disable
// every node's local hard stop. §8.1 cites D-034 (the witness policy is local,
// not a `params` key) as the reason `S_hard` is local at all; a local limit the
// network can raise is not local.
//
// D-060 settles it: `hard_stale` is tested first. A hard limit means what the
// operator typed.
//
// The fixture builds the trap itself. Genesis sets `staleness: 600` and
// `log/29-params` raises it to 900, so `S_hard = 700` — legal and sensible
// while `S` was 600 — lands in the overlap with no reconfiguration.

func TestAHardLimitBelowTheNetworksStalenessStillFires(t *testing.T) {
	limits := Limits{Staleness: 900 * time.Second, Hard: 700 * time.Second}

	// Inside the overlap: past this node's own limit, but not past the
	// network's. The operator asked to drop everything past 700.
	if got := limits.State(800*time.Second, true); got != HardStale {
		t.Errorf("elapsed 800s with S_hard 700s and S 900s is %q; a hard limit the "+
			"network's `staleness` can override is not a limit, and `staleness` "+
			"moves by root quorum", got)
	}

	// The boundary is the same shape as the staleness one: `elapsed > S_hard`
	// is the violation, so sitting exactly on it has not crossed it.
	if got := limits.State(700*time.Second, true); got != Fresh {
		t.Errorf("elapsed exactly equal to S_hard is %q; the rule is "+
			"`elapsed > S_hard`, so the boundary has not been crossed", got)
	}

	// And the ordering must not cost the states below it: with no hard limit
	// configured, nothing changes.
	open := Limits{Staleness: 900 * time.Second}
	if got := open.State(800*time.Second, true); got != Fresh {
		t.Errorf("with no S_hard configured, elapsed 800s under S 900s is %q, want %q",
			got, Fresh)
	}
}

// ...and the suite has to pin it too, or a second implementation reading the
// table the other way round passes everything. No shipped case reached the
// overlap: every one had `S_hard` 3600 above `S` 900, which is exactly why
// run 11's `HardBeforeFresh` variant survived 622 checks.
func TestTheOverlapRegionIsVectored(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "detect", "staleness.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Staleness int64 `json:"staleness"`
		Cases     []struct {
			Name    string `json:"name"`
			Elapsed int64  `json:"elapsed"`
			Hard    *int64 `json:"hard"`
			Expect  string `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	var overlap int
	for _, c := range doc.Cases {
		if c.Hard == nil || *c.Hard == 0 {
			continue
		}
		if *c.Hard < doc.Staleness && c.Elapsed > *c.Hard && c.Elapsed <= doc.Staleness {
			overlap++
			if c.Expect != HardStale {
				t.Errorf("%s sits in the overlap (S_hard %d < elapsed %d ≤ S %d) and "+
					"expects %q; D-060 says the hard limit wins",
					c.Name, *c.Hard, c.Elapsed, doc.Staleness, c.Expect)
			}
		}
	}
	if overlap == 0 {
		t.Error("no case has `hard` below `staleness` with `elapsed` between them, " +
			"so nothing separates testing `fresh` first from testing `hard_stale` " +
			"first — which is the variant that passed all 622 checks in run 11")
	}
}

// D-074 (b). The age of a held checkpoint is the node's estimate of now minus
// that checkpoint's quorum time (§15), and the estimate is the largest lower
// bound the node holds: for every quorum time q it has verified at monotonic
// reading m, q + (now - m). `detect/staleness.json`'s `observed` cases supply
// (quorum time, learned-at) pairs and the instant `now`, and expect the age
// and the state that follow. They separate three readings: §8.1's old
// "monotonic time since this checkpoint was learned", which makes a grown head
// with an older quorum time look younger than the node knows the world to be;
// "the newest quorum time wins", which lets a newer instant learned late
// replace a larger bound and move the estimate backwards; and §15's.
func TestTheAgeIsTheEstimateOfNowMinusTheQuorumTime(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "detect", "staleness.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Staleness int64 `json:"staleness"`
		Hard      int64 `json:"hard"`
		Cases     []struct {
			Name     string     `json:"name"`
			Observed [][2]int64 `json:"observed"`
			Now      int64      `json:"now"`
			Held     int64      `json:"held"`
			Elapsed  int64      `json:"elapsed"`
			Expect   string     `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	limits := Limits{
		Staleness: time.Duration(doc.Staleness) * time.Second,
		Hard:      time.Duration(doc.Hard) * time.Second,
	}
	var derived int
	for _, c := range doc.Cases {
		if len(c.Observed) == 0 {
			continue
		}
		derived++
		var clock Clock
		for _, pair := range c.Observed {
			clock.Observe(time.Unix(pair[0], 0), time.Duration(pair[1])*time.Second)
		}
		age, ok := clock.Age(time.Unix(c.Held, 0), time.Duration(c.Now)*time.Second)
		if !ok {
			t.Errorf("%s: no clock after %d observations", c.Name, len(c.Observed))
			continue
		}
		if age != time.Duration(c.Elapsed)*time.Second {
			t.Errorf("%s: age %s, the suite says %ds", c.Name, age, c.Elapsed)
		}
		if got := limits.State(age, true); got != c.Expect {
			t.Errorf("%s: state %q, the suite says %q", c.Name, got, c.Expect)
		}
	}
	if derived < 3 {
		t.Errorf("%d cases derive the age from observations; the three readings need "+
			"a case each", derived)
	}
}
