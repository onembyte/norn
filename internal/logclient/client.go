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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/freshness"
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
	// Policy is the network's `c2sp.org/tlog-policy`, verbatim from the trust
	// file. It says which witnesses must have cosigned before this node will
	// believe a checkpoint -- §10 step 3, and the difference between "the log
	// operator says this is the log" and "somebody else saw this too".
	Policy string
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

	// The hash tiles must match the tree too. A verifier could skip them --
	// it rebuilt the tree from the bundles, which is stronger than trusting
	// tiles -- but then a log serving corrupt tiles would be broken for every
	// monitor and witness that fetches them, and the one program guaranteed to
	// be looking would say nothing. `norn verify` is that program.
	if err := checkTiles(f, tree); err != nil {
		return nil, err
	}

	return &Result{Checkpoint: cp, SignedCheckpoint: string(raw),
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
		entries, err := decodeBundle(raw)
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

func decodeBundle(raw []byte) ([][]byte, error) {
	var out [][]byte
	for len(raw) > 0 {
		if len(raw) < 2 {
			return nil, logErrorf("truncated entry bundle")
		}
		n := int(binary.BigEndian.Uint16(raw[:2]))
		if len(raw) < 2+n {
			return nil, logErrorf("entry bundle claims %d bytes but has %d", n, len(raw)-2)
		}
		out = append(out, raw[2:2+n])
		raw = raw[2+n:]
	}
	return out, nil
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
