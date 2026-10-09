// These vectors write the detect directory.

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/tlogstore"
)

// writeDetectCases ships the sequences §10's stored-checkpoint block needs.
//
// Everything else in the suite is one artifact judged on its own. These are
// *pairs*: what a node already holds, and what it is then offered. Cold gate
// run 7's implementation contained none of §10's stored block, none of §11's
// four duties and no staleness rule, and scored 241/241 -- because nothing in
// the suite was ever a second checkpoint shown to the same reader.
//
// The four outcomes a reader has to tell apart:
//
//   - a larger consistent head: accept it;
//   - a smaller head of the same log: refuse it, and do not call it a fork --
//     an accusation that cannot be proved must not be made;
//   - a different root at the same size: prove a fork;
//   - a *shorter* divergent branch: prove a fork, not a rollback. This is the
//     one a careless reader files under "logs do not shrink", and it is how a
//     forking log would hide.
func writeDetectCases(root, origin string, key ed25519.PrivateKey, entries [][]byte,
	signed string, signers []cosignpkg.Signer) error {

	dir := filepath.Join(root, "detect")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	divergent, err := forkEntry(root)
	if err != nil {
		return err
	}

	// An honest earlier view of this same log, served with its own tiles.
	honest, err := serveInto(filepath.Join(dir, "honest-earlier"), origin, key,
		entries[:forkAt], signers)
	if err != nil {
		return err
	}
	// A branch that diverges at the same size as that earlier view.
	sameSize := append(append([][]byte(nil), entries[:forkAt-1]...), divergent)
	if _, err := serveInto(filepath.Join(dir, "fork-same-size"), origin, key,
		sameSize, signers); err != nil {
		return err
	}
	// A branch that diverges and is *shorter* than the full log: the case a
	// careless reader files under "logs do not shrink".
	shorter := append(append([][]byte(nil), entries[:forkAt]...), divergent)
	if _, err := serveInto(filepath.Join(dir, "fork-shorter"), origin, key,
		shorter, signers); err != nil {
		return err
	}

	// Cold gate run 12, D4. A branch that diverges below the stored size and
	// then grows past it: the most ordinary equivocation there is, and the
	// shape detect/ did not have. A reader that compares the branches only
	// when the served head is the same size or shorter accepts it.
	longer := append(append([][]byte(nil), entries[:forkAt-1]...), divergent)
	longer = append(longer, entries[forkAt:forkAt+20]...)
	if _, err := serveInto(filepath.Join(dir, "fork-longer"), origin, key,
		longer, signers); err != nil {
		return err
	}
	// Cold gate run 12, D5. This log, honestly signed, with one byte of one
	// entry changed in transit. Its entries do not hash to its head (§10.1
	// step 9, `head`) and, recomputed at the stored size, they disagree with
	// the stored head too -- so a reader that compares branches before it
	// checks the head accuses an honest log of forking, permanently.
	if _, err := serveInto(filepath.Join(dir, "tampered-current"), origin, key,
		entries, signers); err != nil {
		return err
	}
	bundle := filepath.Join(dir, "tampered-current",
		filepath.FromSlash(tlog.EntryBundlePath(0, len(entries)%tlog.TileWidth)))
	tampered, err := os.ReadFile(bundle)
	if err != nil {
		return err
	}
	tampered[len(tampered)-1] ^= 0x01
	if err := os.WriteFile(bundle, tampered, 0o644); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, "earlier.checkpoint"),
		[]byte(honest), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "current.checkpoint"),
		[]byte(signed), 0o644); err != nil {
		return err
	}

	// §8.1's condition 4: the staleness ladder. `params.staleness` travels all
	// the way into `state.json` and, until this file, was read by nothing.
	// `elapsed` is monotonic time since the quorum time was learned (§5.3), so
	// these cases are a table over a pure function and need no artifacts.
	stale := map[string]any{
		"staleness": 900,
		"hard":      3600,
		"cases": []map[string]any{
			{"name": "fresh", "elapsed": 0, "expect": "fresh"},
			{"name": "at-the-staleness-boundary", "elapsed": 900, "expect": "fresh"},
			{"name": "one-second-past", "elapsed": 901, "expect": "degraded"},
			{"name": "past-hard", "elapsed": 3601, "expect": "hard_stale"},
			{"name": "no-clock", "elapsed": 0, "have_clock": false, "expect": "unknown"},
			// Cold gate run 9, D9. `S_hard` is opt-in, and zero means NOT
			// CONFIGURED -- not "no headroom". Every other case here carries
			// 3600, so a reader that read 0 as a limit of zero passed the whole
			// suite while dropping every peer the moment a view went stale,
			// which is the outcome §8.1's asymmetry exists to prevent.
			{"name": "unconfigured-hard-stays-degraded", "elapsed": 100000,
				"hard": 0, "expect": "degraded"},
			{"name": "unconfigured-hard-still-fresh", "elapsed": 0,
				"hard": 0, "expect": "fresh"},
			// Cold gate run 11, D1 (D-060). Every case above has `hard` 3600
			// ABOVE `staleness` 900, so the region where both `fresh` and
			// `hard_stale` hold was unreachable and `HardBeforeFresh` -- the
			// table read the other way round -- passed all 622 checks. The
			// fixture builds this trap itself: genesis sets `staleness` 600
			// and `log/29-params` raises it to 900, so a node that chose
			// S_hard 700 lands in the overlap with no reconfiguration.
			{"name": "hard-below-staleness", "elapsed": 800,
				"hard": 700, "expect": "hard_stale"},
			{"name": "at-the-hard-boundary", "elapsed": 700,
				"hard": 700, "expect": "fresh"},
			// D-074 (b). `elapsed` is §15's age: the node's estimate of now
			// minus the held checkpoint's quorum time, the estimate being the
			// largest lower bound it holds -- for every quorum time q verified
			// at monotonic m, q + (now - m). These cases give the observations
			// and derive `elapsed`; a reader that computes it any other way
			// gets another number. The first separates §15 from §8.1's old
			// "monotonic time since this checkpoint was learned" (that reads
			// 100 and says fresh); the second separates it from "the newest
			// quorum time wins" (that reads 600 and says fresh: a newer instant
			// learned late replaced a larger bound and moved the estimate
			// backwards); the third is the estimate not moving backwards for an
			// older time, which every reading agrees on and is vectored for
			// the one that forgets.
			{"name": "later-head-older-quorum-time", "elapsed": 1200,
				"observed": [][2]int64{{10000, 0}, {9000, 100}}, "now": 200, "held": 9000,
				"expect": "degraded"},
			{"name": "newer-quorum-time-keeps-the-larger-bound", "elapsed": 1000,
				"observed": [][2]int64{{9900, 0}, {10000, 500}}, "now": 1000, "held": 9900,
				"expect": "degraded"},
			{"name": "older-quorum-time-does-not-move-the-estimate-back", "elapsed": 100,
				"observed": [][2]int64{{10000, 0}, {9000, 100}}, "now": 100, "held": 10000,
				"expect": "fresh"},
		},
		"comment": "SPEC 8.1's ladder as a table: `elapsed` is the " +
			"held checkpoint's age under SPEC 15 -- the node's estimate of now, the " +
			"largest lower bound it holds (each verified quorum time plus the " +
			"monotonic time since it was learned), minus the checkpoint's quorum " +
			"time; cases with `observed` give the (quorum time, learned-at) pairs and " +
			"`now` that derive it -- " +
			"`staleness` is the network's own from params, and `hard` is this node's " +
			"local S_hard. The rule is `elapsed > staleness`, so the boundary is still " +
			"fresh. A node with no corroborated instant has no clock and reports " +
			"`unknown` rather than guessing. A case may carry its own `hard`, " +
			"overriding the top-level one: zero means S_hard is NOT CONFIGURED, " +
			"not a limit of zero, so such a node stays `degraded` however old the " +
			"view gets rather than dropping every peer. The states are tested in " +
			"SPEC 8.1's order and the first that holds is the answer: `hard_stale` " +
			"comes BEFORE `fresh`, so a node whose own S_hard is tighter than the " +
			"network's staleness goes hard-stale at its own limit -- see " +
			"`hard-below-staleness`, which is the only case separating the two " +
			"readings of the table",
	}
	staleBlob, err := json.MarshalIndent(stale, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "staleness.json"),
		append(staleBlob, '\n'), 0o644); err != nil {
		return err
	}

	meta := map[string]any{
		"cases": []map[string]string{
			{"name": "accept-grown", "stored": "earlier.checkpoint", "serve": "../served",
				"outcome": "accept", "says": "a head that grows on the one this node holds"},
			{"name": "refuse-shrunk", "stored": "current.checkpoint", "serve": "honest-earlier",
				"outcome": "refuse", "says": "a log does not shrink"},
			{"name": "fork-at-the-same-size", "stored": "earlier.checkpoint",
				"serve": "fork-same-size", "outcome": "fork",
				"says": "two roots at one size"},
			{"name": "fork-on-a-shorter-branch", "stored": "current.checkpoint",
				"serve": "fork-shorter", "outcome": "fork",
				"says": "shorter and divergent is a fork, not a rollback"},
			// Cold gate run 9, D10. §10 says a node that does not hold `at`
			// MUST NOT accuse -- and inside §10's own loop it always holds
			// `at`, because it stores a checkpoint only after replaying to it.
			// The clause is for a reader holding a stored head WITHOUT the
			// branch: a monitor that has been handed a checkpoint, or a node
			// restarted from its stored one. Such a reader cannot tell a fork
			// from a rollback, so it refuses and says so.
			{"name": "shorter-with-no-held-branch", "stored": "current.checkpoint",
				"serve": "fork-shorter", "outcome": "refuse", "held": "none",
				"says": "a log does not shrink"},
			{"name": "fork-on-a-longer-branch", "stored": "earlier.checkpoint",
				"serve": "fork-longer", "outcome": "fork",
				"says": "a grown head is compared at the stored size too"},
			{"name": "tampered-bundle-under-a-stored-head", "stored": "current.checkpoint",
				"serve": "tampered-current", "outcome": "refuse",
				"says": "do not hash to the advertised head"},
		},
		// D-061, §10.1: the code each case that is not accepted is refused
		// with. tampered-bundle-under-a-stored-head is `head`, not `fork`:
		// the head is checked before the branches are compared.
		"codes": map[string]refusal.Code{
			"refuse-shrunk":                       refusal.Rollback,
			"fork-at-the-same-size":               refusal.Fork,
			"fork-on-a-shorter-branch":            refusal.Fork,
			"shorter-with-no-held-branch":         refusal.Rollback,
			"fork-on-a-longer-branch":             refusal.Fork,
			"tampered-bundle-under-a-stored-head": refusal.Head,
		},
		"comment": "pairs, not single artifacts. `stored` is the checkpoint this reader " +
			"already holds, over the entries in `../served`; `serve` is the log it is " +
			"then offered, tiles and all, as a real log would serve it. §10's " +
			"stored-checkpoint block and §11's duties are reached by nothing else here. " +
			"fork-on-a-shorter-branch is the one that matters most: it is what a forking " +
			"log looks like when it hides behind \"logs do not shrink\"",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}

// serveInto writes a complete tlog-tiles directory over exactly these entries
// and returns its signed head. A branch that is offered to a reader has to
// come with the tiles that back it, exactly as a real log would serve them.
func serveInto(dir, origin string, key ed25519.PrivateKey, entries [][]byte,
	signers []cosignpkg.Signer) (string, error) {

	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	store, err := tlogstore.Open(dir, origin, key, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(staggeredCosigner(signers))))
	if err != nil {
		return "", err
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			return "", err
		}
	}
	return store.SignedCheckpoint()
}
