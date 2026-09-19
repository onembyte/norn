package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/trust"
)

func verifyCmd(args []string) error {
	fs := newFlagSet("verify")
	trustPath := fs.String("trust", "", "path to norn.trust (required)")
	logLocation := fs.String("log", "", "log URL or directory; defaults to the first log_urls entry")
	asJSON := fs.Bool("json", false, "print the canonical state instead of a summary")
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

	result, err := logclient.Verify(fetcher,
		replay.Anchor{Net: anchor.Net, GenesisHash: anchor.GenesisHash})
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
	return nil
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
