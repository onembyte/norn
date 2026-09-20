package freshness

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
)

// `GOSSIP.md` part 5 defines the node's only trusted clock: the latest instant
// that enough witnesses vouch for. It words that as "the k-th newest
// cosignature timestamp", which is right for a flat threshold and meaningless
// for a nested policy -- `group top 1 inner friend` has no single k. The
// definition that survives both is the one implemented here: the latest T at
// which the policy is satisfied by the witnesses whose cosignature is at least
// T.

func witnessKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("norn/freshness-test/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func vkey(name string) string {
	return note.CosignerVerifierKey("norn-witness/"+name,
		witnessKey(name).Public().(ed25519.PublicKey))
}

// rules builds a policy whose witness lines are the named parties, plus
// whatever group and quorum lines the caller adds.
func rules(t *testing.T, names []string, tail string) *policy.Policy {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "log norn/test %s\n", note.VerifierKey("norn/test",
		witnessKey("log").Public().(ed25519.PublicKey)))
	for _, name := range names {
		fmt.Fprintf(&b, "witness %s %s\n", name, vkey(name))
	}
	b.WriteString(tail)
	p, err := policy.Parse(b.String())
	if err != nil {
		t.Fatalf("policy: %v\n%s", err, b.String())
	}
	return p
}

// at builds cosignatures from `name:unixtime` pairs.
func at(pairs ...any) []cosign.Cosignature {
	var out []cosign.Cosignature
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, cosign.Cosignature{
			Name: "norn-witness/" + pairs[i].(string),
			Time: time.Unix(int64(pairs[i+1].(int)), 0),
		})
	}
	return out
}

func TestQuorumTimeIsTheLatestInstantEnoughWitnessesVouchFor(t *testing.T) {
	names := []string{"pi", "vps", "friend"}

	for _, tc := range []struct {
		name  string
		tail  string
		signs []cosign.Cosignature
		want  int64
	}{
		{
			// Two of three: the newest time at which two have signed is the
			// second-newest timestamp. Not the newest -- one witness alone is
			// not a quorum, so its later signature vouches for nothing.
			"two of three", "group home 2 pi vps friend\nquorum home\n",
			at("pi", 300, "vps", 200, "friend", 100), 200,
		},
		{
			"any one of three", "group home any pi vps friend\nquorum home\n",
			at("pi", 300, "vps", 200, "friend", 100), 300,
		},
		{
			"all three", "group home all pi vps friend\nquorum home\n",
			at("pi", 300, "vps", 200, "friend", 100), 100,
		},
		{
			// A single witness named directly as the quorum.
			"one named witness", "quorum pi\n",
			at("pi", 300, "vps", 200), 300,
		},
		{
			// The case a k-th-newest implementation gets wrong. `top` is met
			// either by `friend` alone or by both of `inner`. At 500 only pi
			// has signed, so inner is short and friend is absent: not
			// satisfied. At 400 both of inner have signed. The answer is 400,
			// while "the 1st newest timestamp" would say 500.
			"nested groups have no single k",
			"group inner 2 pi vps\ngroup top 1 inner friend\nquorum top\n",
			at("pi", 500, "vps", 400, "friend", 100), 400,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := QuorumTime(rules(t, names, tc.tail), tc.signs)
			if !ok {
				t.Fatal("no quorum time, want one")
			}
			if got.Unix() != tc.want {
				t.Errorf("quorum time = %d, want %d", got.Unix(), tc.want)
			}
		})
	}
}

// Not enough witnesses have signed for the policy to be met at any instant, so
// there is no time this node may treat as now.
func TestNoQuorumMeansNoClock(t *testing.T) {
	p := rules(t, []string{"pi", "vps", "friend"}, "group home 2 pi vps friend\nquorum home\n")

	if _, ok := QuorumTime(p, at("pi", 300)); ok {
		t.Error("one of two witnesses produced a quorum time")
	}
	if _, ok := QuorumTime(p, nil); ok {
		t.Error("no cosignatures at all produced a quorum time")
	}
}

// A witness the policy never names cannot move the clock, however recent its
// cosignature -- the same property that stops it making up the quorum.
func TestAnUnnamedWitnessDoesNotMoveTheClock(t *testing.T) {
	p := rules(t, []string{"pi", "vps", "friend"}, "group home 2 pi vps friend\nquorum home\n")

	got, ok := QuorumTime(p, at("pi", 300, "vps", 200, "stranger", 900))
	if !ok {
		t.Fatal("no quorum time")
	}
	if got.Unix() != 200 {
		t.Errorf("quorum time = %d, want 200: a stranger moved the clock", got.Unix())
	}
}

// `quorum none` is a network that asked for no corroboration. It is a valid
// configuration, and it has no witness clock: nobody vouches for any instant,
// so freshness is unknown rather than perfect.
func TestQuorumNoneHasNoClock(t *testing.T) {
	p := rules(t, []string{"pi"}, "quorum none\n")

	if _, ok := QuorumTime(p, at("pi", 300)); ok {
		t.Error("a policy that requires no witness produced a witness clock")
	}
}
