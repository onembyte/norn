package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/trust"
)

// verifyEvidenceCmd checks a fork evidence file offline.
//
// This is the command the artifact exists for (`GOSSIP.md` part 7): it reaches
// nothing, trusts nobody, and needs only the file and a trust document the
// reader already had. The reader is assumed to be sceptical -- a witness
// operator, or somebody who was sent a blog post -- so every claim in the file
// is re-derived here rather than reported.
func verifyEvidenceCmd(args []string) error {
	fs := newFlagSet("verify-evidence")
	trustPath := fs.String("trust", "", "path to norn.trust (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *trustPath == "" || fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("usage: norn verify-evidence -trust norn.trust <file>")
	}

	raw, err := os.ReadFile(*trustPath)
	if err != nil {
		return err
	}
	anchor, err := trust.Parse(raw)
	if err != nil {
		return err
	}
	if err := anchor.Validate(); err != nil {
		return fmt.Errorf("the trust file is not a usable anchor: %w", err)
	}

	body, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	evidence, err := forkevidence.Parse(body)
	if err != nil {
		return err
	}

	// The reader's own policy decides the quorum, never the one inside the
	// file: §11.1's premise is that there is no reason to trust whoever handed
	// it over, and §11 rule 4 makes a fork conclusion permanent.
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		return fmt.Errorf("the trust file's own policy does not parse: %w", err)
	}
	finding, err := forkevidence.Check(evidence, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
	if err != nil {
		// A file that does not prove a fork is the *good* outcome for a reader
		// checking an accusation, so say which it is rather than only failing.
		return fmt.Errorf("this file does not prove a fork: %w", err)
	}

	fingerprint, _ := anchor.Fingerprint()
	fmt.Printf("FORK PROVEN\n\n")
	fmt.Printf("network     %s  (%s)\n", anchor.Name, anchor.Origin)
	fmt.Printf("anchor      %s\n", fingerprint)
	fmt.Printf("at size     %d entries\n", finding.Size)
	fmt.Printf("  root A    %s\n", hex.EncodeToString(finding.Held[:]))
	fmt.Printf("  root B    %s\n", hex.EncodeToString(finding.Claimed[:]))
	fmt.Printf("\nThe log signed two different trees at the same size, and a quorum of\n")
	fmt.Printf("this network's witnesses cosigned both. That is not something a log can\n")
	fmt.Printf("do by accident, and nothing in this check needed the network to be\n")
	fmt.Printf("running or the accuser to be trusted.\n\n")
	fmt.Printf("Witnesses that were meant to prevent it: %v\n", rules.WitnessNames())
	return nil
}
