package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/refusal"
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
	logLocation := fs.String("log", "", "a log URL or directory to learn what this network "+
		"published since the trust file (§9.4); without it, the trust file alone")
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
	// it over, and §11 rule 4 makes a fork conclusion permanent. "The reader's
	// own" is the trust file's, or -- with -log -- what the network's roots
	// published since, as a node verifies under (§10, §9.4; SEC-005 b, c).
	keys, policyText := []string{anchor.LogKey}, anchor.Policy
	source := "the trust file"
	if *logLocation != "" {
		if keys, policyText, err = published(anchor, *logLocation); err != nil {
			return fmt.Errorf("could not learn what this network published from %s: %w", *logLocation, err)
		}
		source = fmt.Sprintf("the trust file and what %s published (%d log key(s))", *logLocation, len(keys))
	}
	rules, err := policy.Parse(policyText)
	if err != nil {
		return fmt.Errorf("the reader's own policy does not parse: %w", err)
	}
	finding, err := forkevidence.Check(evidence, anchor.Origin, keys, policyText)
	if err != nil {
		// A file that does not prove a fork is the *good* outcome for a reader
		// checking an accusation, so say which it is rather than only failing.
		return fmt.Errorf("this file does not prove a fork: %w", err)
	}

	fingerprint, _ := anchor.Fingerprint()
	fmt.Printf("FORK PROVEN\n\n")
	fmt.Printf("network     %s  (%s)\n", anchor.Name, anchor.Origin)
	fmt.Printf("anchor      %s\n", fingerprint)
	fmt.Printf("checked by  %s\n", source)
	if finding.Split == 0 {
		fmt.Printf("split: none claimed\n")
	} else {
		fmt.Printf("split: %d\n", finding.Split)
	}
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

// published is what a reader learns from a network's log: the trust file's
// log key plus every key its roots published, and the published policy where
// there is one. The log is untrusted, so it is learned the way a restarted
// node learns it (D-069): the log must verify under the trust file, or --
// when the trust file's key or policy is what refuses it -- under what its
// own entries publish, replayed from the pinned genesis, which is root-signed
// authority (§9.4). A log that verifies under neither teaches nothing.
func published(anchor *trust.Trust, location string) ([]string, string, error) {
	fetcher, err := logclient.Open(location)
	if err != nil {
		return nil, "", err
	}
	under := anchorFor(anchor)
	result, err := logclient.Verify(fetcher, under)
	if code, _ := refusal.CodeOf(err); code == refusal.LogSignature || code == refusal.Quorum {
		if st, perr := logclient.Published(fetcher, under.Anchor); perr == nil {
			under.LogKeys = append(under.LogKeys, logclient.KeysFrom(anchor.Origin, st)...)
			if p := logclient.PolicyFrom(st); p != "" {
				under.Policy = p
			}
			result, err = logclient.Verify(fetcher, under)
		}
	}
	if err != nil {
		return nil, "", err
	}
	keys := append([]string{anchor.LogKey}, logclient.KeysFrom(anchor.Origin, result.State)...)
	policyText := anchor.Policy
	if p := logclient.PolicyFrom(result.State); p != "" {
		policyText = p
	}
	return keys, policyText, nil
}
