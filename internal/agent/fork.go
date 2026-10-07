package agent

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/onembyte/norn/internal/durable"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/logclient"
)

// ForkDir holds the evidence a node wrote when it caught its log equivocating.
//
// Its presence is also the freeze: §11 says a forked node refuses every later
// inconsistent checkpoint **forever**, and "forever" has to outlive the
// process or it means "until somebody reboots the machine" -- which is a thing
// an attacker can arrange.
const ForkDir = "fork"

// Fork alarms a proven equivocation. It is the loudest thing Norn can say: a
// log signed two histories and a quorum of witnesses vouched for both.
const Fork = "FORK"

// Frozen reports that a node is refusing to move because of a fork it already
// proved. It repeats, because a frozen node doing nothing looks exactly like a
// working one.
const Frozen = "FROZEN_BY_FORK"

// Frozen reports whether this node has proof its log forked, and so will
// accept nothing further under this anchor.
func (a *Agent) Frozen() bool { return a.frozen }

// loadFreeze looks for evidence this node wrote earlier under this anchor.
//
// Evidence is filed per network, so §11's escape hatch works as written:
// "until an operator explicitly resets with a new trust file". A different
// anchor is a different network to this node, and the old evidence stays on
// disk, because it is still what an operator takes to the witness operators.
func (a *Agent) loadFreeze() {
	var matches []string
	// Evidence first, so a node that has both names the evidence; then the
	// markers a node left when it had proved a fork and could not file it.
	for _, pattern := range []string{"*.evidence", "*.frozen"} {
		for _, dir := range a.stateDirs() {
			found, err := filepath.Glob(filepath.Join(dir, ForkDir, pattern))
			if err == nil {
				matches = append(matches, found...)
			}
		}
	}
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if strings.HasSuffix(path, ".frozen") {
			lines := strings.SplitN(string(raw), "\n", 3)
			if len(lines) >= 2 && lines[0] == freezeMagic && lines[1] == a.cfg.Anchor.Origin {
				a.frozen, a.frozenBy = true, path
				return
			}
			continue // torn, or somebody else's network
		}
		evidence, err := forkevidence.Parse(raw)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(evidence.Held, a.cfg.Anchor.Origin+"\n") {
			continue // somebody else's network
		}
		a.frozen, a.frozenBy = true, path
		return
	}
}

// pollEvidence asks peers whether anybody has proved a fork this node has not
// seen. It is T1b: "a node that never saw the second branch freezes via peer
// evidence".
//
// Evidence is checked independently of checkpoint gossip. A proven fork can
// reach a node even when its own log and the sampled peer checkpoints look
// consistent, so evidence polling runs on its own T_g schedule.
//
// A peer's evidence is believed only because it is **checked**, by the same
// `forkevidence.Check` a stranger would run against the same trust file.
// Rubbish from a neighbour cannot freeze a network; genuine evidence means
// there genuinely is a fork, whoever hands it over.
func (a *Agent) pollEvidence() {
	if a.frozen || a.cfg.Peers == nil {
		return
	}
	mono := a.cfg.Mono()
	if a.evidenceAskedSet && mono-a.evidenceAsked < a.cfg.GossipEvery {
		return
	}
	a.evidenceAsked, a.evidenceAskedSet = mono, true

	for _, addr := range gossip.Choose(a.cfg.Peers(), a.fanout(), a.peerOrder) {
		raw, err := gossip.Peer(addr).Fetch("evidence")
		if err != nil {
			continue // almost every peer, almost always
		}
		evidence, err := forkevidence.Parse(raw)
		if err != nil {
			a.emit(Event{Kind: PeerRefused, Message: fmt.Sprintf(
				"peer %s served something that is not evidence: %v", addr, err)})
			continue
		}
		if _, err := forkevidence.Check(evidence, a.cfg.Anchor.Origin,
			a.cfg.Anchor.LogKey, a.cfg.Anchor.Policy); err != nil {
			a.emit(Event{Kind: PeerRefused, Message: fmt.Sprintf(
				"peer %s served evidence that proves nothing: %v", addr, err)})
			continue
		}
		a.adoptEvidence(addr, raw)
		return
	}
}

// adoptEvidence freezes on a fork somebody else proved, and keeps a copy so
// this node can pass it on in turn.
func (a *Agent) adoptEvidence(from string, raw []byte) {
	a.frozen = true
	path, err := a.storeEvidence(raw)
	if err != nil {
		kept := "and no freeze marker could be kept either"
		if marker, markErr := a.freezeWithoutEvidence(fmt.Sprintf(
			"peer %s proved a fork; its evidence could not be kept: %v", from, err)); markErr == nil {
			a.frozenBy, kept = marker, "a freeze marker is kept at "+marker
		} else {
			kept += " (" + markErr.Error() + ")"
		}
		a.emit(Event{Kind: Fork, Message: fmt.Sprintf(
			"peer %s proved this network's log forked, and the evidence could not "+
				"be kept (%v); %s. This node will accept nothing further (§11).", from, err, kept)})
		return
	}
	a.frozenBy = path
	a.emit(Event{Kind: Fork, Message: fmt.Sprintf(
		"peer %s proved this network's log signed two histories, and this node "+
			"checked it against its own trust file. Evidence kept at %s. Nothing "+
			"further will be accepted until a new trust file (§11); the peer table "+
			"is unchanged.", from, path)})
}

// storeEvidence files evidence, whoever produced it, as §11's
// `fork/<unix>.evidence`.
func (a *Agent) storeEvidence(raw []byte) (string, error) {
	return a.fileInForkDir(".evidence", raw)
}

// freezeMagic opens a freeze marker, `fork/<unix>.frozen`: the file a node
// writes when it has proved a fork but could not file the evidence (SEC-005
// (a)). Its presence is the freeze, exactly as an evidence file's is -- §11's
// "forever" cannot depend on the evidence being writable. It proves nothing
// to anybody else, so gossip never serves it; the FORK alarm carries the
// reason.
const freezeMagic = "norn-freeze/v1"

// freezeWithoutEvidence persists the freeze when there is no evidence to
// persist it with: the magic line, this network's origin, and why.
func (a *Agent) freezeWithoutEvidence(reason string) (string, error) {
	marker := freezeMagic + "\n" + a.cfg.Anchor.Origin + "\n" + reason + "\n"
	return a.fileInForkDir(".frozen", []byte(marker))
}

// fileInForkDir writes a file under `fork/` named by the second it was
// written in, with the extension given.
//
// Its presence is the freeze, so it is written durably (internal/durable): a
// power cut leaves the file whole or absent, never torn. And a file already
// there is never rewritten. The same bytes filed again are the same file;
// anything else -- a second fork in the same second, the evidence of the
// network this node ran before a reset, a copy torn by a crash before writes
// were durable -- keeps its name, and this piece takes the next free second.
// Names stay unix seconds, so their order is still the order they were filed
// in, which is how gossip picks the newest (internal/gossip).
func (a *Agent) fileInForkDir(ext string, raw []byte) (string, error) {
	if a.stateDir() == "" {
		return "", errors.New("no state directory to keep evidence in")
	}
	dir := filepath.Join(a.stateDir(), ForkDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	start := a.cfg.Now().Unix()
	for second := start; second < start+maxEvidenceProbe; second++ {
		path := filepath.Join(dir, fmt.Sprintf("%d%s", second, ext))
		existing, err := os.ReadFile(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := durable.WriteFile(path, raw, 0o644); err != nil {
				return "", err
			}
			return path, nil
		case err != nil:
			return "", err
		case bytes.Equal(existing, raw):
			return path, nil
		}
	}
	return "", fmt.Errorf("no free name in %s within %d seconds of now", dir, maxEvidenceProbe)
}

// maxEvidenceProbe bounds the search for a free name. A node files evidence
// once per fork, so reaching it means the directory holds something other
// than what this node wrote, and saying so beats looping.
const maxEvidenceProbe = 1 << 10

// recordFork carries out §11: evidence, alarm, freeze. The caller is
// responsible for the fourth duty -- leaving the stored checkpoint and the
// peer table exactly as they were -- which it does by returning without
// touching either.
func (a *Agent) recordFork(fork *logclient.ForkError) {
	a.frozen = true

	path, err := a.writeEvidence(fork)
	if err != nil {
		// A node that could not write the file is still forked, and the
		// freeze must outlive this process all the same (§11): a marker
		// stands in for the evidence, and saying so matters more than either
		// file does.
		kept := "and no freeze marker could be kept either"
		if marker, markErr := a.freezeWithoutEvidence(fmt.Sprintf("%v: %v", fork, err)); markErr == nil {
			a.frozenBy, kept = marker, "a freeze marker is kept at "+marker
		} else {
			kept += " (" + markErr.Error() + ")"
		}
		a.emit(Event{Kind: Fork, Message: fmt.Sprintf(
			"%v -- and the evidence could not be written (%v); %s", fork, err, kept)})
		return
	}
	a.emit(Event{Kind: Fork, Message: fmt.Sprintf(
		"this log signed two histories: at %d entries it gives %s where this node "+
			"holds %s, and a quorum of witnesses cosigned both. Evidence: %s. This "+
			"node will accept nothing further until it is given a new trust file "+
			"(§11); the peer table is unchanged.",
		fork.At, short(fork.Conflicting.Root[:]), short(fork.HeldRoot[:]), path)})
}

// writeEvidence builds the artifact and puts it where an operator will find it.
func (a *Agent) writeEvidence(fork *logclient.ForkError) (string, error) {
	if a.stateDir() == "" {
		return "", errors.New("no state directory to write evidence to")
	}
	held := a.held()
	if held == nil {
		return "", errors.New("nothing held to compare against")
	}
	// §11.1's `held` is the branch the accuser can speak for, because it has
	// the entries. At or below the stored size that is this node's own
	// branch, and the served tree -- the one under suspicion -- is what it is
	// accused with: evidence drawn from the accused would be the accused
	// certifying the accusation. When the served branch is the LONGER one,
	// this node's branch does not reach the conflicting head's size and
	// cannot speak for it -- but the node has just fetched every served
	// entry, so that is the branch it can now speak for: the served head is
	// `held`, this node's stored head is `conflicting`, and the disagreement
	// is at the stored size. Built only one way, a log that forked and then
	// grew past this node's head raised FORK, wrote nothing, and was unfrozen
	// by the next restart (SEC-005 (a)) -- and growing past the victim is the
	// natural shape of a forking log.
	var evidence *forkevidence.Evidence
	var err error
	if fork.Conflicting.Size > fork.Stored.Size {
		evidence, err = forkevidence.Build(fork.Tree, fork.Signed,
			held.SignedCheckpoint, fork.Stored)
	} else {
		evidence, err = forkevidence.Build(fork.Held, held.SignedCheckpoint,
			fork.Signed, fork.Conflicting)
	}
	if err != nil {
		return "", err
	}
	evidence.Policy = a.cfg.Anchor.Policy

	// Check the node's own work before filing it. Evidence that does not
	// prove anything is worse than none: it is an accusation somebody will
	// check and dismiss.
	if _, err := forkevidence.Check(evidence, a.cfg.Anchor.Origin,
		a.cfg.Anchor.LogKey, a.cfg.Anchor.Policy); err != nil {
		return "", fmt.Errorf("this node built evidence that does not prove a fork: %w", err)
	}

	raw, err := evidence.Encode()
	if err != nil {
		return "", err
	}
	path, err := a.storeEvidence(raw)
	if err != nil {
		return "", err
	}
	a.frozenBy = path
	return path, nil
}

func short(hash []byte) string { return hex.EncodeToString(hash[:8]) }
