package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/plainlog"
	"github.com/onembyte/norn/internal/policy"
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

	fmt.Print(freshnessLine(result.QuorumTime, result.Cosignatures, anchor.Policy, now))
	at := proven.EvaluationTime(result)
	if at.IsZero() {
		fmt.Println("expiry      no witness time; expiry not judged")
	} else {
		fmt.Printf("expiry      expiry judged at %s (witness time)\n", at.UTC().Format(time.RFC3339))
	}
	printPeers(result.State, at)
	printRecent(result, recent, now)
}

// freshnessLine reports what this command is allowed to say about the age of
// what it is looking at.
//
// `GOSSIP.md` part 5 puts the clock in witness time, because a node's own wall
// clock is untrusted (A11). A running `nornd` measures age from there with a
// monotonic reading; a one-shot command has no such history -- it has just
// fetched a checkpoint and knows only what the cosignatures say. So it reports
// the instant the quorum vouched for as fact, and any age it derives from that
// is explicitly the local clock's opinion.
func freshnessLine(quorumTime *time.Time, cosignatures []cosign.Cosignature,
	policyText string, now time.Time) string {
	var b strings.Builder
	if quorumTime == nil {
		fmt.Fprintf(&b, "freshness   UNKNOWN — no witness has cosigned this checkpoint\n")
		fmt.Fprintf(&b, "            A checkpoint carries no timestamp, and this node's own clock is\n")
		fmt.Fprintf(&b, "            not evidence (A11), so the fresh/degraded state cannot be\n")
		fmt.Fprintf(&b, "            computed at all.\n")
		return b.String()
	}

	quorum := "—"
	if rules, err := policy.Parse(policyText); err == nil {
		quorum = rules.Quorum()
	}
	fmt.Fprintf(&b, "freshness   cosigned %s by %d witness(es), quorum %q\n",
		quorumTime.UTC().Format(time.RFC3339), len(cosignatures), quorum)
	fmt.Fprintf(&b, "            age %s by this machine's clock — local time is not evidence\n",
		now.Sub(*quorumTime).Round(time.Second))
	fmt.Fprintf(&b, "            (A11); the fresh/degraded state is tracked by a running nornd,\n")
	fmt.Fprintf(&b, "            which measures elapsed time monotonically.\n")
	return b.String()
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
