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
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlog"
)

// ErrLog reports a log that cannot be trusted: unreachable, inconsistent, or
// serving entries that do not match the head it advertises.
var ErrLog = errors.New("log error")

func logErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrLog, fmt.Sprintf(format, args...))
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
}

// Anchor is everything a verifier is allowed to start from: the network it is
// for, the genesis entry it pins, and the keys whose signature on a checkpoint
// it will accept (SPEC §9).
type Anchor struct {
	replay.Anchor
	// LogKeys are signed-note verifier keys. At least one must have signed the
	// checkpoint. More than one appears during a `log_key` rotation, where old
	// and new are both valid for `overlap` (`ENROLLMENT.md` part 6).
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
	if len(anchor.LogKeys) == 0 {
		return nil, logErrorf("the anchor carries no log key; §10 requires the " +
			"checkpoint signature to be checked, and there is nothing to check it against")
	}
	// An empty genesis hash would not be lenient -- replay would abort every
	// log with `bad-genesis` -- but it would be silent: an empty state reads
	// like a network with no devices rather than like a caller mistake. This
	// exact slip cost an afternoon in 2.9e-ii, in a test helper whose JSON tag
	// did not match `genesis_hash`.
	if len(anchor.GenesisHash) != sha256.Size {
		return nil, logErrorf("the anchor pins no genesis entry (%d-byte hash); "+
			"without it a log for any other network would replay to an empty state",
			len(anchor.GenesisHash))
	}
	raw, err := f.Fetch("checkpoint")
	if err != nil {
		return nil, logErrorf("fetching the checkpoint: %v", err)
	}
	cp, err := tlog.Verify(string(raw), anchor.LogKeys)
	if err != nil {
		return nil, logErrorf("the checkpoint is not signed by a key this anchor "+
			"trusts: %v", err)
	}
	if anchor.Origin != "" && cp.Origin != anchor.Origin {
		return nil, logErrorf("the checkpoint is for origin %q, and this anchor is for %q",
			cp.Origin, anchor.Origin)
	}

	// Then the witnesses. A log can sign anything it likes, including two
	// different histories for two different nodes; what it cannot do is get a
	// quorum of witnesses to cosign both at the same size.
	cosignatures, quorumTime, err := checkQuorum(anchor, string(raw))
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
	if tree.Size() != cp.Size {
		return nil, logErrorf("checkpoint claims %d entries, %d were served",
			cp.Size, tree.Size())
	}
	if tree.Head() != cp.Root {
		return nil, logErrorf("the served entries do not hash to the advertised head")
	}

	// §10: a log only grows, and it contains everything it used to contain.
	if err := checkAgainstStored(anchor.Stored, cp, tree, string(raw), anchor.Held); err != nil {
		return nil, err
	}

	// The hash tiles must match the tree too. A verifier could skip them --
	// it rebuilt the tree from the bundles, which is stronger than trusting
	// tiles -- but then a log serving corrupt tiles would be broken for every
	// monitor and witness that fetches them, and the one program guaranteed to
	// be looking would say nothing. `norn verify` is that program.
	if err := checkTiles(f, tree); err != nil {
		return nil, err
	}

	return &Result{Checkpoint: cp, SignedCheckpoint: string(raw), Tree: tree,
		Cosignatures: cosignatures, QuorumTime: quorumTime,
		State: replay.Replay(anchor.Anchor, entries), Served: entries}, nil
}

// fetchEntries reads entry bundles until it has `size` entries.
func fetchEntries(f Fetcher, size int64) ([][]byte, error) {
	var out [][]byte
	for index := int64(0); int64(len(out)) < size; index++ {
		remaining := size - int64(len(out))
		width := tlog.TileWidth
		if remaining < int64(width) {
			width = int(remaining)
		}
		raw, err := fetchBundle(f, index, width)
		if err != nil {
			return nil, err
		}
		entries, err := tlog.DecodeBundle(raw)
		if err != nil {
			return nil, err
		}
		if len(entries) == 0 {
			return nil, logErrorf("entry bundle %d is empty", index)
		}
		out = append(out, entries...)
	}
	if int64(len(out)) != size {
		return nil, logErrorf("served %d entries, the checkpoint claims %d", len(out), size)
	}
	return out, nil
}

// fetchBundle tries the full path first, then the partial one: a bundle is
// full unless it is the last, and the last carries its width in its path.
func fetchBundle(f Fetcher, index int64, width int) ([]byte, error) {
	if raw, err := f.Fetch(tlog.EntryBundlePath(index, tlog.TileWidth)); err == nil {
		return raw, nil
	}
	raw, err := f.Fetch(tlog.EntryBundlePath(index, width))
	if err != nil {
		return nil, logErrorf("fetching entry bundle %d: %v", index, err)
	}
	return raw, nil
}

// checkTiles requires every hash tile the tree implies to be served, and to be
// the bytes the tree says.
func checkTiles(f Fetcher, tree *tlog.Tree) error {
	tiles, err := tree.Tiles()
	if err != nil {
		return logErrorf("computing the expected tiles: %v", err)
	}
	for _, tile := range tiles {
		served, err := f.Fetch(tile.Path())
		if err != nil {
			return logErrorf("the log does not serve %s, which tlog-tiles requires: %v",
				tile.Path(), err)
		}
		if !bytes.Equal(served, tile.Data) {
			return logErrorf("the hash tile at %s is not what the entries imply; "+
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
		return nil, nil, logErrorf("%v", err)
	}
	names := make([]string, 0, len(cosignatures))
	for _, c := range cosignatures {
		names = append(names, rules.Label(c.Name))
	}
	if !rules.Satisfied(names) {
		return nil, nil, logErrorf("the checkpoint does not satisfy the witness policy: "+
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
			return logErrorf("this checkpoint has %d entries and this node already "+
				"holds %d; a log does not shrink, and replaying an earlier view "+
				"would undo every revocation since", cp.Size, stored.Size)
		}
		if mine, err = held.HeadAt(at); err != nil {
			return logErrorf("checking this node's own branch at size %d: %v", at, err)
		}
	}
	if served != mine {
		return &ForkError{Stored: *stored, Conflicting: cp, Tree: tree,
			At: at, Signed: signed, HeldRoot: mine, Held: held}
	}
	if cp.Size < stored.Size {
		return logErrorf("this checkpoint has %d entries and this node already holds "+
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
