package ots

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// CheckAnchor reads a `.ots` proof and reports what it says about a
// checkpoint.
//
// The stamped value is `sha256` of the checkpoint **body** -- origin, size and
// root, without the signature lines. That is the whole claim an anchor makes:
// *this tree existed by then*. The log's signature is deliberately not
// included, for two reasons. It is unstable, because cosignatures are appended
// as witnesses answer, so a note-level digest would stop matching the moment a
// witness replied. And it would add nothing: the log is the party an anchor
// exists to constrain, so binding the claim to the log's own signature proves
// nothing extra about when the tree existed.
func CheckAnchor(raw []byte, checkpointBody string) (*AnchorReport, error) {
	proof, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return Report(proof, checkpointBody)
}

// AnchorReport is what a node can say about an anchor without a blockchain.
type AnchorReport struct {
	// Chains is true when every operation really does lead from this
	// checkpoint to the values the attestations commit to.
	Chains bool
	// Earliest is the lowest-numbered chain attestation, which is the
	// strongest backdating claim in the proof. Nil when nothing is confirmed.
	Earliest *ChainClaim
	// Confirmed and Pending count the two kinds of branch.
	Confirmed, Pending int
	// Unknown counts attestation types this build does not recognise, which
	// are reported rather than dropped: a proof may legitimately carry more
	// than Norn knows about.
	Unknown int
}

// ChainClaim is a block a proof commits into.
type ChainClaim struct {
	Chain  string
	Height uint64
	// Commitment is the value that block is claimed to contain. Checking that
	// it does needs the chain; nothing here does it.
	Commitment []byte
}

// Report walks an already-parsed proof against a checkpoint body.
func Report(proof *Proof, checkpointBody string) (*AnchorReport, error) {
	digest := sha256.Sum256([]byte(checkpointBody))
	results, err := proof.Walk(digest[:])
	if err != nil {
		return nil, err
	}

	report := &AnchorReport{Chains: true}
	for _, r := range results {
		switch {
		case r.Attestation.Bitcoin(), r.Attestation.Litecoin():
			report.Confirmed++
			claim := &ChainClaim{Chain: r.Attestation.Kind(),
				Height: r.Attestation.Height, Commitment: r.Commitment}
			if report.Earliest == nil || claim.Height < report.Earliest.Height {
				report.Earliest = claim
			}
		case r.Attestation.Pending():
			report.Pending++
		default:
			report.Unknown++
		}
	}
	return report, nil
}

// Summary is the line an operator reads.
//
// It is written to be impossible to misread as more than it is. Norn walked
// the operations; it did not ask a blockchain whether the commitment is in the
// block, because it has no blockchain to ask. Saying so every time is cheaper
// than one person concluding otherwise once.
func (r *AnchorReport) Summary() string {
	var b strings.Builder
	if r.Earliest != nil {
		fmt.Fprintf(&b, "anchored: the proof commits this checkpoint into %s block %d "+
			"(that the block contains it is not checked here -- it needs a %s node)",
			r.Earliest.Chain, r.Earliest.Height, r.Earliest.Chain)
	} else {
		b.WriteString("not yet anchored: the proof chains from this checkpoint, but " +
			"every branch is still a calendar's promise rather than a block")
	}
	if r.Pending > 0 {
		fmt.Fprintf(&b, "; %d branch(es) still pending at a calendar", r.Pending)
	}
	if r.Unknown > 0 {
		fmt.Fprintf(&b, "; %d attestation(s) of a kind this build does not know", r.Unknown)
	}
	return b.String()
}
