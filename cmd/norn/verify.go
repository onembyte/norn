package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/ots"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/trust"
)

// anchorFor turns a trust file into what a verifier may start from: the
// network, the genesis it pins, and the log key whose signature on a
// checkpoint it will accept (§9, §10).
func anchorFor(t *trust.Trust) logclient.Anchor {
	return logclient.Anchor{
		Anchor:  replay.FromTrust(t),
		LogKeys: []string{t.LogKey},
		Origin:  t.Origin,
		Policy:  t.Policy,
	}
}

func verifyCmd(args []string) error {
	fs := newFlagSet("verify")
	trustPath := fs.String("trust", "", "path to norn.trust (required)")
	logLocation := fs.String("log", "", "log URL or directory; defaults to the first log_urls entry")
	asJSON := fs.Bool("json", false, "print the canonical state instead of a summary")
	anchored := fs.Bool("anchored", false,
		"also report the OpenTimestamps proof in anchors/, if there is one (advisory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *trustPath == "" {
		fs.Usage()
		return fmt.Errorf("-trust is required: a verifier without an anchor verifies nothing")
	}

	anchor, err := loadAnchor(*trustPath)
	if err != nil {
		return err
	}

	location := *logLocation
	if location == "" {
		location = anchor.LogURLs[0]
	}
	fetcher, err := logclient.Open(location)
	if err != nil {
		return err
	}

	result, err := logclient.Verify(fetcher, anchorFor(anchor))
	if err != nil {
		return err
	}

	if *asJSON {
		out, err := result.State.MarshalCanonical()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(out)
		return err
	}
	printSummary(anchor, result)
	if *anchored {
		reportAnchor(fetcher, result)
	}
	return nil
}

// reportAnchor says what `anchors/<size>.ots` claims about this checkpoint.
//
// It never returns an error, and that is D-009 rather than laziness: anchoring
// is an **advisory** witness type. A node that refused a perfectly good log
// because an optional extra was missing, unreadable or for other bytes would
// be enforcing the opposite of what the decision says -- and would hand
// anybody who can delete a file a way to stop a network working.
//
// What it will do is say exactly what it found, including "this proof is for a
// different document", which is what a checkpoint edited after stamping looks
// like.
func reportAnchor(fetcher logclient.Fetcher, result *logclient.Result) {
	path := fmt.Sprintf("anchors/%d.ots", result.Checkpoint.Size)
	raw, err := fetcher.Fetch(path)
	if err != nil {
		fmt.Printf("anchor     no anchor served at %s (advisory; D-009)\n", path)
		return
	}

	body, _, _ := strings.Cut(result.SignedCheckpoint, "\n\n")
	report, err := ots.CheckAnchor(raw, body+"\n\n")
	if err != nil {
		fmt.Printf("anchor     UNUSABLE: %v\n", err)
		fmt.Printf("           A stamp that does not chain from this checkpoint is what\n")
		fmt.Printf("           an edit after stamping looks like. It changes nothing the\n")
		fmt.Printf("           log proves (D-009), and it is worth asking about.\n")
		return
	}
	fmt.Printf("anchor     %s\n", report.Summary())
}

// printSummary says what a verifier concluded and, just as importantly, what
// it refused: a run that rejected entries but prints only the good news would
// be the wrong shape of tool.
func printSummary(anchor *trust.Trust, result *logclient.Result) {
	fp, _ := anchor.Fingerprint()
	fmt.Printf("network    %s\n", anchor.Name)
	fmt.Printf("anchor     %s\n", fp)
	fmt.Printf("origin     %s\n", result.Checkpoint.Origin)
	fmt.Printf("size       %d entries\n", result.Checkpoint.Size)
	fmt.Printf("root       %s\n", hex.EncodeToString(result.Checkpoint.Root[:]))

	st := result.State
	ids := make([]string, 0, len(st.Devices))
	for id := range st.Devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var active int
	for _, id := range ids {
		if st.Devices[id].Status == state.StatusActive {
			active++
		}
	}
	fmt.Printf("\n%d device(s), %d active:\n", len(ids), active)
	for _, id := range ids {
		d := st.Devices[id]
		marker := " "
		if d.Status == state.StatusActive {
			marker = "*"
		}
		fmt.Printf("  %s %-14s %s  wg %s…\n", marker, id, d.Status, d.WgPk[:16])
	}

	if len(st.Rejected) > 0 {
		fmt.Printf("\n%d entr(ies) rejected:\n", len(st.Rejected))
		counts := map[string]int{}
		for _, r := range st.Rejected {
			counts[r.Reason]++
		}
		reasons := make([]string, 0, len(counts))
		for reason := range counts {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		for _, reason := range reasons {
			fmt.Printf("  %-16s %d\n", reason, counts[reason])
		}
	}
}
