// Package logclient reads a served Norn log and verifies it: the verifier loop
// of SPEC.md §10.
//
// A log is fetched through a Fetcher, so the same code reads a directory on
// disk, a static web server, or a peer over the tunnel. The interface is one
// method wide on purpose -- everything a verifier needs from a log is "give me
// the bytes at this path", and keeping it that narrow is what makes gossip
// (§6) a different Fetcher rather than a different verifier.
package logclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	upstream "golang.org/x/mod/sumdb/tlog"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/freshness"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlog"
)

// ErrLog reports a log that cannot be trusted: unreachable, inconsistent, or
// serving entries that do not match the head it advertises.
var ErrLog = errors.New("log error")

// ErrEmptyLog is the `genesis` refusal of a log with no entries at all: it has
// not published this network's genesis yet. It is still a refusal -- an empty
// log enforces nothing -- but a caller waiting for the genesis to be included
// can tell it from a log whose entry 0 is another network's, which never will.
var ErrEmptyLog = errors.New("the log has no entries, so no entry 0 to be this network's genesis")

func logErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrLog, fmt.Sprintf(format, args...))
}

// refuse is a log error carrying the §10.1 code of the step that refused
// (D-061). Every refusal of what a log served goes through here or through
// carry; what is wrong with the anchor goes through logErrorf alone, because
// it is the caller's configuration and §10.1's codes describe the log.
func refuse(code refusal.Code, format string, args ...any) error {
	return refusal.Wrap(code, logErrorf(format, args...))
}

// carry is a log error for a refusal a lower layer already named: tlog and
// cosign make their own checks and attach their own codes. A cause that
// arrives uncoded was the anchor's fault, and stays uncoded.
func carry(cause error, format string, args ...any) error {
	return refusal.Carry(cause, logErrorf(format, args...))
}

// checkpointRefusal says, per code, what tlog.Verify found wrong.
var checkpointRefusal = map[refusal.Code]string{
	refusal.Note:         "the checkpoint is not a well-formed signed note",
	refusal.LogSignature: "the checkpoint is not signed by a key this anchor trusts",
	refusal.Checkpoint:   "the signed text is not a checkpoint",
	"":                   "the anchor's log keys are unusable",
}

// Fetcher returns the bytes at a log-relative path, or an error.
type Fetcher interface {
	Fetch(path string) ([]byte, error)
}

// Dir serves a log from a directory on disk.
type Dir string

// Fetch implements Fetcher.
func (d Dir) Fetch(path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(string(d), filepath.FromSlash(path)))
}

// Result is what a successful verification yields.
type Result struct {
	Checkpoint tlog.Checkpoint
	State      *state.State
	// SignedCheckpoint is the head exactly as the log published it. A parsed
	// checkpoint is a fact; the note is the *evidence* for it, and a proof
	// bundle has to carry the evidence (§8.1).
	SignedCheckpoint string
	// Cosignatures are the witnesses that vouched for this head, with the
	// times they said it was. Witness time is the only clock a node may use
	// (A11), so this is what freshness is computed from.
	Cosignatures []cosign.Cosignature
	// QuorumTime is the instant the policy vouches for -- the newest time at
	// which enough witnesses had signed (GOSSIP part 5). It is nil when the
	// policy asks for no corroboration, because then nobody is vouching for
	// the time either, and a node with no witness clock must say so rather
	// than fall back to its own (A11).
	QuorumTime *time.Time
	// Tree is the log as served, rebuilt from those entries. A node keeps it
	// so it can speak for its own branch later -- which is what tells a fork
	// apart from a rollback.
	Tree *tlog.Tree
	// Served is every entry the log served, in log order. A caller that has
	// just verified a log usually wants to look something up in it -- an
	// inclusion check, a proof bundle -- and re-fetching would be asking a
	// second time for bytes already proven to belong to this head.
	Served [][]byte
	// fold is the replay that produced State, kept so a later verification
	// can resume it from here instead of replaying the whole log (H4).
	fold *replay.Replayer
}

// Anchor is everything a verifier is allowed to start from: the network it is
// for, the genesis entry it pins, and the keys whose signature on a checkpoint
// it will accept (SPEC §9).
type Anchor struct {
	replay.Anchor
	// LogKeys are signed-note verifier keys. At least one must have signed the
	// checkpoint. More than one appears across a `log_key` rotation, and none
	// is ever retired: keys accumulate (§9.4), so the anchor's key stays valid
	// alongside every key the roots later published.
	LogKeys []string
	// Origin is the network's origin line, verbatim from the trust file. A
	// checkpoint says which log it is about in its first line, and until §10
	// said to compare it nothing did: the note name and key id bind the
	// *signer*, not the subject.
	Origin string
	// Policy is the network's `c2sp.org/tlog-policy`, verbatim from the trust
	// file. It says which witnesses must have cosigned before this node will
	// believe a checkpoint -- §10 step 3, and the difference between "the log
	// operator says this is the log" and "somebody else saw this too".
	Policy string
	// Stored is the head this node already holds, if any. §10 requires a new
	// checkpoint to be at least as large and to contain it.
	//
	// Nil means "nothing held yet", which is only true at first contact.
	// Passing nil when a node *does* hold a head disables the one check that
	// stops a log -- or a peer -- serving a correctly signed, correctly
	// cosigned view of its own past.
	Stored *tlog.Checkpoint
	// Held is the node's own tree for the stored head, when it has one.
	//
	// Without it a log that forks by serving a **shorter** branch can only be
	// refused for shrinking: at a smaller size the served tree cannot say what
	// the node's branch had, so "consistent prefix" and "different history"
	// are indistinguishable. With it they are told apart, and the second gets
	// the evidence §11 requires.
	Held *tlog.Tree
}

// Verify fetches a log, checks that the log operator signed the head, checks
// that enough witnesses cosigned it, checks that the entries it serves really
// do hash to that head, and replays them under the anchor.
//
// The order matters twice over. The **signature comes first**: an unsigned
// head is a claim nobody made, and everything below it would be arithmetic
// about an anonymous document. Then integrity BEFORE replay -- replaying first
// and checking afterwards would mean acting on entries that were never shown
// to belong to the log, exactly the trust a transparency log exists to remove.
func Verify(f Fetcher, anchor Anchor) (*Result, error) {
	raw, cp, cosignatures, quorumTime, err := verifyHead(f, anchor)
	if err != nil {
		return nil, err
	}

	entries, err := fetchEntries(f, cp.Size)
	if err != nil {
		return nil, err
	}

	// Rebuild the tree from what was served and require the advertised head.
	tree, err := tlog.Build(entries)
	if err != nil {
		return nil, logErrorf("building the tree: %v", err)
	}
	return finish(f, anchor, raw, cp, cosignatures, quorumTime, tree, entries, replay.New(anchor.Anchor), nil)
}

// VerifyFrom verifies a log as Verify does, starting from the head this node
// holds (H4-b): it fetches only the entry bundles that hold an entry at or
// past the held size and only the hash tiles whose path is new, appends the
// new entries to a copy of the held tree, and resumes a copy of the held
// replay. The consistency of held→new is the appending itself: if the served
// head is the head of the held tree with the new entries appended, the served
// log contains the held one (§10), with no proof from anyone.
//
// What it cannot see it does not judge. The entries and tiles below the held
// size were verified when that head was adopted; a defect planted there since
// is for the periodic full verification (H3), not for every cycle. And where
// the cheap path cannot decide -- a head that is not the held tree extended,
// a size below the held one, a head whose bundles below the held size do not
// match -- it hands the whole question to Verify, so that whatever the answer
// is, it is the same answer, code for code. A held result without a tree or
// a fold is verified in full too.
func VerifyFrom(held *Result, f Fetcher, anchor Anchor) (*Result, error) {
	if held == nil || held.Tree == nil || held.fold == nil ||
		int64(len(held.Served)) != held.Tree.Size() || held.Tree.Size() == 0 {
		return Verify(f, anchor)
	}
	raw, cp, cosignatures, quorumTime, err := verifyHead(f, anchor)
	if err != nil {
		return nil, err
	}
	from := held.Tree.Size()
	if cp.Size < from {
		return Verify(f, anchor) // a rollback or a fork on a shorter branch: §10 decides
	}

	// The bundles from the one the held size falls in. Its entries below the
	// held size must be the held ones -- a log that re-wrote them is not an
	// extension of what this node holds, whatever its head says.
	var fresh [][]byte
	for index := from / tlog.TileWidth; cp.Size > from && index*tlog.TileWidth < cp.Size; index++ {
		width := int(min(cp.Size-index*tlog.TileWidth, tlog.TileWidth))
		bundle, err := fetchBundle(f, index, width)
		if err != nil {
			return nil, err
		}
		entries, err := tlog.DecodeBundle(bundle)
		if err != nil {
			return nil, refuse(refusal.Entries, "entry bundle %d does not frame: %v", index, err)
		}
		if len(entries) != width {
			return nil, refuse(refusal.Entries, "entry bundle %d holds %d entries; a checkpoint "+
				"of %d implies %d", index, len(entries), cp.Size, width)
		}
		for i, raw := range entries {
			at := index*tlog.TileWidth + int64(i)
			if at < from {
				if !bytes.Equal(raw, held.Served[at]) {
					return Verify(f, anchor)
				}
				continue
			}
			fresh = append(fresh, raw)
		}
	}
	tree := held.Tree.Clone()
	for _, raw := range fresh {
		if err := tree.Append(raw); err != nil {
			return nil, logErrorf("building the tree: %v", err)
		}
	}
	if tree.Head() != cp.Root {
		return Verify(f, anchor) // `head`, or a fork below the held size: §10 decides
	}
	entries := append(append([][]byte(nil), held.Served...), fresh...)
	heldTiles, err := held.Tree.Tiles()
	if err != nil {
		return nil, logErrorf("computing the held tiles: %v", err)
	}
	unchanged := make(map[string]bool, len(heldTiles))
	for _, tile := range heldTiles {
		unchanged[tile.Path()] = true
	}
	return finish(f, anchor, raw, cp, cosignatures, quorumTime, tree, entries, held.fold.Clone(), unchanged)
}

// verifyHead is the part of §10 that reads only the checkpoint: the anchor's
// own soundness, the log signature, the origin and the witness quorum.
func verifyHead(f Fetcher, anchor Anchor) (string, tlog.Checkpoint, []cosign.Cosignature, *time.Time, error) {
	var none tlog.Checkpoint
	if len(anchor.LogKeys) == 0 {
		return "", none, nil, nil, logErrorf("the anchor carries no log key; §10 requires the " +
			"checkpoint signature to be checked, and there is nothing to check it against")
	}
	// An empty genesis hash would not be lenient -- replay would abort every
	// log with `bad-genesis` -- but it would be silent: an empty state reads
	// like a network with no devices rather than like a caller mistake. This
	// exact slip cost an afternoon in 2.9e-ii, in a test helper whose JSON tag
	// did not match `genesis_hash`.
	if len(anchor.GenesisHash) != sha256.Size {
		return "", none, nil, nil, logErrorf("the anchor pins no genesis entry (%d-byte hash); "+
			"without it a log for any other network would replay to an empty state",
			len(anchor.GenesisHash))
	}
	raw, err := f.Fetch("checkpoint")
	if err != nil {
		return "", none, nil, nil, refuse(refusal.Unserved, "fetching the checkpoint: %v", err)
	}
	cp, err := tlog.Verify(string(raw), anchor.LogKeys)
	if err != nil {
		code, _ := refusal.CodeOf(err)
		return "", none, nil, nil, carry(err, "%s: %v", checkpointRefusal[code], err)
	}
	if anchor.Origin != "" && cp.Origin != anchor.Origin {
		return "", none, nil, nil, refuse(refusal.Origin, "the checkpoint is for origin %q, and this anchor is for %q",
			cp.Origin, anchor.Origin)
	}

	// Then the witnesses. A log can sign anything it likes, including two
	// different histories for two different nodes; what it cannot do is get a
	// quorum of witnesses to cosign both at the same size.
	cosignatures, quorumTime, err := checkQuorum(anchor, string(raw))
	if err != nil {
		return "", none, nil, nil, err
	}
	return string(raw), cp, cosignatures, quorumTime, nil
}

// checkGenesis is §10.1's `genesis` (D-074 (g)): a log with no entry 0, or
// whose entry 0 is not the genesis this anchor pins -- replaying it alone
// aborts with bad-genesis -- is not this network's log, and nothing in it is a
// fact about this network. Before this was the verifier's, a correctly signed
// and cosigned log for another genesis verified, replayed to nothing, and an
// owner node installed the nothing (SEC-029); only the node refused it, so
// `norn verify` and the monitor said "ok".
//
// It runs after the comparison with a held head, never before (D-074 (g) as
// amended 2026-10-10): to a node that holds a head, another history signed by
// the same log is equivocation, and the `fork` that proves it -- or the
// `rollback` an empty log is -- must not be hidden behind this code. A verifier
// with nothing to compare reaches this step and gets `genesis`.
func checkGenesis(anchor replay.Anchor, entries [][]byte) error {
	if len(entries) == 0 {
		return refusal.Wrap(refusal.Genesis, fmt.Errorf("%w: %w; a log that has not "+
			"published its genesis enforces nothing", ErrLog, ErrEmptyLog))
	}
	if replay.Replay(anchor, entries[:1]).Size == 0 {
		return refuse(refusal.Genesis, "the log's entry 0 is not this network's genesis "+
			"(replay aborts with %s); nothing in it is this network's", replay.ReasonBadGenesis)
	}
	return nil
}

// finish is the rest of §10 once the tree is in hand: the head, the stored
// comparison, the tiles (all of them, or only those not in `unchanged`) and
// the replay, resumed on `fold`.
func finish(f Fetcher, anchor Anchor, raw string, cp tlog.Checkpoint, cosignatures []cosign.Cosignature,
	quorumTime *time.Time, tree *tlog.Tree, entries [][]byte, fold *replay.Replayer,
	unchanged map[string]bool) (*Result, error) {
	if tree.Size() != cp.Size {
		return nil, refuse(refusal.Entries, "checkpoint claims %d entries, %d were served",
			cp.Size, tree.Size())
	}
	if tree.Head() != cp.Root {
		return nil, refuse(refusal.Head, "the served entries do not hash to the advertised head")
	}

	// §10: a log only grows, and it contains everything it used to contain.
	if err := checkAgainstStored(anchor.Stored, cp, tree, raw, anchor.Held); err != nil {
		return nil, err
	}
	if err := checkGenesis(anchor.Anchor, entries); err != nil {
		return nil, err
	}

	// The hash tiles must match the tree too. A verifier could skip them --
	// it rebuilt the tree from the bundles, which is stronger than trusting
	// tiles -- but then a log serving corrupt tiles would be broken for every
	// monitor and witness that fetches them, and the one program guaranteed to
	// be looking would say nothing. `norn verify` is that program.
	if err := checkTiles(f, tree, unchanged); err != nil {
		return nil, err
	}

	// The fold is applied to what it has not seen: all of it for a fresh one,
	// the entries past its size for one resumed.
	state := fold.Apply(entries[fold.State().Size:]...)
	return &Result{Checkpoint: cp, SignedCheckpoint: raw, Tree: tree,
		Cosignatures: cosignatures, QuorumTime: quorumTime,
		State: state, Served: entries, fold: fold}, nil
}

// fetchEntries reads the entry bundles a checkpoint of `size` implies.
//
// The size fixes how many bundles there are and how many entries each one
// holds: every bundle but the last holds tlog.TileWidth, and the last holds
// the rest. A bundle holding any other number is refused here, as §10.1's
// `entries`. Counting across bundles instead -- reading on until `size`
// entries have arrived -- sends a verifier after a bundle the size never
// implied when one comes up short, and it refuses `unserved` for a log that
// served every file it was asked for.
func fetchEntries(f Fetcher, size int64) ([][]byte, error) {
	var out [][]byte
	for index := int64(0); int64(len(out)) < size; index++ {
		width := int(min(size-int64(len(out)), int64(tlog.TileWidth)))
		raw, err := fetchBundle(f, index, width)
		if err != nil {
			return nil, err
		}
		entries, err := tlog.DecodeBundle(raw)
		if err != nil {
			return nil, refuse(refusal.Entries, "entry bundle %d does not frame: %v", index, err)
		}
		if len(entries) != width {
			return nil, refuse(refusal.Entries, "entry bundle %d holds %d entries; a checkpoint "+
				"of %d implies %d", index, len(entries), size, width)
		}
		out = append(out, entries...)
	}
	return out, nil
}

// fetchBundle prefers the checkpoint's exact width. A peer may have published
// a full bundle since we read its previous checkpoint, while still retaining
// the partial that checkpoint requires. Trying the full path first would then
// fetch too many entries and refuse a usable previous head.
func fetchBundle(f Fetcher, index int64, width int) ([]byte, error) {
	if raw, err := f.Fetch(tlog.EntryBundlePath(index, width)); err == nil {
		return raw, nil
	}
	raw, err := f.Fetch(tlog.EntryBundlePath(index, tlog.TileWidth))
	if err != nil {
		return nil, refuse(refusal.Unserved, "fetching entry bundle %d: %v", index, err)
	}
	return raw, nil
}

// checkTiles requires every hash tile the tree implies to be served, and to be
// the bytes the tree says.
// `unchanged` names tiles the held head already vouched for (by path, width
// included, so an identical path is identical bytes); nil means check all.
func checkTiles(f Fetcher, tree *tlog.Tree, unchanged map[string]bool) error {
	tiles, err := tree.Tiles()
	if err != nil {
		return logErrorf("computing the expected tiles: %v", err)
	}
	for _, tile := range tiles {
		if unchanged[tile.Path()] {
			continue
		}
		served, err := f.Fetch(tile.Path())
		if err != nil {
			return refuse(refusal.Unserved, "the log does not serve %s, which tlog-tiles requires: %v",
				tile.Path(), err)
		}
		if !bytes.Equal(served, tile.Data) {
			return refuse(refusal.Tiles, "the hash tile at %s is not what the entries imply; "+
				"this log is broken for anyone fetching proofs from it", tile.Path())
		}
	}
	return nil
}

// checkQuorum applies the network's policy to the checkpoint's cosignatures.
func checkQuorum(anchor Anchor, signed string) ([]cosign.Cosignature, *time.Time, error) {
	if anchor.Policy == "" {
		return nil, nil, logErrorf("the anchor carries no policy; §10 requires the witness " +
			"quorum to be checked, and there is nothing to check it against")
	}
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		return nil, nil, logErrorf("the anchor's policy is unusable: %v", err)
	}

	cosignatures, err := cosign.Verify(signed, rules.Keys())
	if err != nil {
		return nil, nil, carry(err, "%v", err)
	}
	names := make([]string, 0, len(cosignatures))
	for _, c := range cosignatures {
		if label, ok := rules.LabelFor(c.Name, c.Public); ok {
			names = append(names, label)
		}
	}
	if !rules.Satisfied(names) {
		return nil, nil, refuse(refusal.Quorum, "the checkpoint does not satisfy the witness policy: "+
			"quorum %q, cosigned by %v", rules.Quorum(), names)
	}

	// The same rules that decided the quorum decide the instant it vouches
	// for; reading it anywhere else would be a second opinion about the same
	// question.
	if at, ok := freshness.QuorumTime(rules, cosignatures); ok {
		return cosignatures, &at, nil
	}
	return cosignatures, nil, nil
}

// checkAgainstStored is SPEC §10's comparison with the head this node already
// holds:
//
//	require cp.size >= stored_cp.size
//	verify consistency stored_cp → cp; on failure → FORK (§11)
//
// Both halves matter, and the first is the one that is easy to miss. A
// checkpoint older than the one a node holds is not malformed: it is the same
// log, earlier, signed and cosigned exactly as correctly. Replaying it rolls
// the node's peer table backwards -- a device revoked at entry 80 is active
// again if somebody serves the log as it stood at entry 70. Once a node has
// peers to ask as well as a log, that is a move anybody in the mesh can make.
//
// The consistency half needs no proof from anyone. A node holds every entry
// (`GOSSIP.md` part 6, full replication), so it recomputes what the head at
// the stored size must have been and compares. A mismatch means this log
// cannot have produced the head the node is holding: a fork, not an error.
func checkAgainstStored(stored *tlog.Checkpoint, cp tlog.Checkpoint, tree *tlog.Tree,
	signed string, held *tlog.Tree) error {
	if stored == nil {
		return nil
	}
	// Compare where both trees can speak: the smaller of the two sizes. A
	// disagreement there is a fork whichever way round the sizes fall, and
	// checking it *before* the size rule matters -- a forking log that serves
	// a shorter branch would otherwise be filed as an ordinary rollback and
	// leave no evidence.
	at := min(cp.Size, stored.Size)
	served, err := tree.HeadAt(at)
	if err != nil {
		return logErrorf("checking the stored head against this log: %v", err)
	}
	mine := stored.Root
	if at != stored.Size {
		if held == nil {
			// This node cannot speak for that size, so it cannot tell a fork
			// from a rollback. Refusing as a rollback is the safe half of the
			// answer, and saying so is better than claiming a fork it has not
			// proved.
			return refuse(refusal.Rollback, "this checkpoint has %d entries and this node already "+
				"holds %d; a log does not shrink, and replaying an earlier view "+
				"would undo every revocation since", cp.Size, stored.Size)
		}
		if mine, err = held.HeadAt(at); err != nil {
			return logErrorf("checking this node's own branch at size %d: %v", at, err)
		}
	}
	if served != mine {
		return refusal.Wrap(refusal.Fork, &ForkError{Stored: *stored, Conflicting: cp, Tree: tree,
			At: at, Signed: signed, HeldRoot: mine, Held: held})
	}
	if cp.Size < stored.Size {
		return refuse(refusal.Rollback, "this checkpoint has %d entries and this node already holds "+
			"%d; a log does not shrink, and replaying an earlier view would undo "+
			"every revocation since", cp.Size, stored.Size)
	}
	return nil
}

// ForkError reports two histories that cannot both be this log.
//
// It is typed rather than a message because §11 asks a node to *do* four
// things about it -- write evidence, freeze, alarm, and keep refusing -- and
// none of them can be driven off a formatted string. It carries what the
// evidence needs: both heads, and the tree that can prove what this node held.
type ForkError struct {
	// Stored is the head this node was holding.
	Stored tlog.Checkpoint
	// Conflicting is the head that could not be reconciled with it.
	Conflicting tlog.Checkpoint
	// Tree is the log as served, for computing the proof that binds them.
	Tree *tlog.Tree
	// At is the size the two disagree at.
	At int64
	// Signed is the conflicting head exactly as the log published it, which is
	// what evidence has to carry: a parsed checkpoint is a claim, the note is
	// the signature somebody else can check.
	Signed string
	// HeldRoot is what this node's branch had at `At`, and Held is the tree
	// that can prove it. Evidence is built from these: the *served* tree is
	// the one under suspicion.
	HeldRoot upstream.Hash
	Held     *tlog.Tree
}

func (e *ForkError) Error() string {
	return fmt.Sprintf("%s: FORK: at %d entries this log gives a different head than "+
		"this node holds -- the two histories are not the same log (§11)",
		ErrLog, e.At)
}

func (e *ForkError) Unwrap() error { return ErrLog }

// PolicyFrom is the witness policy a replayed state imposes, or "" if the log
// has published none (D-020, §9.4).
//
// Unlike the log keys, a published policy **replaces** the trust file's rather
// than joining it: a policy is one document, and two of them in force at once
// is exactly the disagreement about the quorum that §4.5 refuses to allow.
// Only the roots can publish one (§4.3), which is what makes that safe.
func PolicyFrom(st *state.State) string {
	if st == nil {
		return ""
	}
	return st.Policy
}

// KeysFrom is the set of signed-note verifier keys a replayed state authorises
// for signing this log's checkpoints, in log order (D-020, §9.4).
//
// The trust file's own key is not among them: it is not in the log. A caller
// adds these to the keys it already trusts rather than replacing them, because
// the point of an overlap window is that both work while operators distribute
// new trust files.
//
// This is the only way a node learns a rotated key, and it is why rotation
// cannot bootstrap itself: reaching the state that names a key requires having
// already accepted a checkpoint under a key the node had beforehand. A stolen
// log key therefore cannot name its own successor -- publishing a `log_key`
// entry takes the root quorum (§4.3).
func KeysFrom(origin string, st *state.State) []string {
	if st == nil {
		return nil
	}
	out := make([]string, 0, len(st.LogKeys))
	for _, key := range st.LogKeys {
		raw, err := hex.DecodeString(key.Pk)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			// Replay refuses a `log_key` entry whose `pk` is not 32 bytes, so
			// this is unreachable from a state this package produced. Skipping
			// rather than failing keeps a caller with a hand-built state from
			// losing the keys that *are* usable.
			continue
		}
		out = append(out, note.VerifierKey(origin, ed25519.PublicKey(raw)))
	}
	return out
}
