package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/plainlog"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/trust"
)

// RecentEntries is how many entries `norn status` reads back in words
// (`ENROLLMENT.md` part 7 rule 5).
const RecentEntries = 5

func statusCmd(args []string) error {
	fs := newFlagSet("status")
	trustPath := fs.String("trust", "", "path to norn.trust (required)")
	logLocation := fs.String("log", "", "log URL or directory; defaults to the anchor's log_urls")
	recent := fs.Int("recent", RecentEntries, "how many recent entries to read back")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *trustPath == "" {
		fs.Usage()
		return errors.New("-trust is required: status without an anchor is a rumour")
	}

	anchor, err := loadAnchor(*trustPath)
	if err != nil {
		return err
	}
	location := *logLocation
	if location == "" {
		if len(anchor.LogURLs) == 0 {
			return errors.New("the anchor lists no log_urls; pass -log")
		}
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

	printStatus(anchor, result, *recent, time.Now())
	return nil
}

func printStatus(anchor *trust.Trust, result *logclient.Result, recent int, now time.Time) {
	fingerprint, _ := anchor.Fingerprint()
	fmt.Printf("network     %s  (%s)\n", anchor.Name, anchor.Origin)
	fmt.Printf("anchor      %s\n", fingerprint)
	fmt.Printf("checkpoint  %d entries, root %s\n", result.Checkpoint.Size,
		hex.EncodeToString(result.Checkpoint.Root[:8]))

	printFreshness(anchor)
	printPeers(result.State, now)
	printRecent(result, recent, now)
}

// printFreshness reports what a node is allowed to know about the age of what
// it is looking at, which right now is nothing.
//
// `GOSSIP.md` part 5 is explicit: witness time is the clock, because a node's
// own wall clock is untrusted (A11). A checkpoint carries no timestamp of its
// own, so until a witness cosigns one, "how old is this view" has no answer --
// and printing the local clock's opinion would be inventing the one number the
// whole freshness design exists to avoid inventing.
func printFreshness(anchor *trust.Trust) {
	fmt.Printf("freshness   UNKNOWN — no witness cosignatures yet\n")
	fmt.Printf("            A checkpoint carries no timestamp, and this node's own clock is\n")
	fmt.Printf("            not evidence (A11). Until one of the %d witness(es) cosigns, the\n",
		len(anchor.Witnesses))
	fmt.Printf("            fresh/degraded/hard-stale state cannot be computed at all.\n")
}

func printPeers(st *state.State, now time.Time) {
	ids := make([]string, 0, len(st.Devices))
	for id := range st.Devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// "Proven" has one definition, in internal/proven, because active and
	// proven differ by exactly an expiry check and two copies of that
	// difference is how an expired contractor stays in a peer table.
	var count, revoked, expired int
	for _, id := range ids {
		d := st.Devices[id]
		switch {
		case d.Status != state.StatusActive:
			revoked++
		case !proven.IsProven(d, now):
			expired++
		default:
			count++
		}
	}
	fmt.Printf("\npeers       %d proven, %d revoked, %d expired\n", count, revoked, expired)
	for _, id := range ids {
		d := st.Devices[id]
		marker, note := " ", string(d.Status)
		switch {
		case d.Status != state.StatusActive:
		case !proven.IsProven(d, now):
			note = "expired " + time.Unix(int64(d.Expires), 0).Format("2006-01-02")
		default:
			marker, note = "*", "proven"
		}
		fmt.Printf("  %s %-16s %-24s wg %s…  since entry %d\n",
			marker, id, note, d.WgPk[:12], d.SinceIndex)
	}

	if len(st.Rejected) > 0 {
		fmt.Printf("\n%d entr(ies) in this log were refused by replay; `norn verify` lists them\n",
			len(st.Rejected))
	}
}

// printRecent is UX rule 5: the last few entries in plain words. An operator
// who cannot read their own log will not notice the entry they did not expect.
func printRecent(result *logclient.Result, recent int, now time.Time) {
	if recent <= 0 || len(result.Served) == 0 {
		return
	}
	refused := map[uint64]string{}
	for _, r := range result.State.Rejected {
		refused[r.Index] = r.Reason
	}

	start := len(result.Served) - recent
	if start < 0 {
		start = 0
	}
	fmt.Printf("\nrecent      (times are the signer's own clock, and advisory)\n")
	for index := start; index < len(result.Served); index++ {
		env, err := entry.Decode(result.Served[index])
		if err != nil {
			fmt.Printf("  %-12s entry %d does not decode\n", "", index)
			continue
		}
		line := fmt.Sprintf("  %-12s %s", plainlog.Ago(env, now), plainlog.Describe(env))
		if reason := refused[uint64(index)]; reason != "" {
			line += fmt.Sprintf("  — REFUSED: %s", reason)
		}
		fmt.Println(line)
	}
}
