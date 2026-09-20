package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/ots"
)

// stampCmd obtains an OpenTimestamps proof for a log's current checkpoint and
// writes it where `norn verify --anchored` looks: `anchors/<size>.ots`.
//
// This is a **monitor's** job, not a node's (`GOSSIP.md` T8). It talks to
// calendars on the public internet, which is exactly the sort of thing that
// must never be on the path that decides whether a peer stays in the peer
// table -- so it is a command an operator runs, and D-009's architecture test
// keeps the daemon from ever importing any of it.
func stampCmd(args []string) error {
	fs := newFlagSet("stamp")
	trustPath := fs.String("trust", "", "path to norn.trust (required)")
	logLocation := fs.String("log", "", "log URL or directory; defaults to the first log_urls entry")
	out := fs.String("out", "", "directory to write anchors/<size>.ots into (required)")
	calendars := fs.String("calendars", "",
		"comma-separated calendar URLs; defaults to the public OpenTimestamps ones")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *trustPath == "" || *out == "" {
		fs.Usage()
		return fmt.Errorf("-trust and -out are required")
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

	// Stamp only what verifies. A proof over a checkpoint this network does
	// not accept would be a timestamp on somebody else's document.
	result, err := logclient.Verify(fetcher, anchorFor(anchor))
	if err != nil {
		return fmt.Errorf("refusing to stamp a log that does not verify: %w", err)
	}

	body, _, _ := strings.Cut(result.SignedCheckpoint, "\n\n")
	digest := sha256.Sum256([]byte(body + "\n\n"))

	where := ots.DefaultCalendars
	if *calendars != "" {
		where = strings.Split(*calendars, ",")
	}
	proof, err := ots.Stamp(digest[:], where)
	if err != nil {
		return err
	}

	dir := filepath.Join(*out, "anchors")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, fmt.Sprintf("%d.ots", result.Checkpoint.Size))
	if err := os.WriteFile(path, proof, 0o644); err != nil {
		return err
	}

	fmt.Printf("stamped    %s\n", path)
	fmt.Printf("checkpoint %d entries, digest %x\n", result.Checkpoint.Size, digest[:8])
	fmt.Printf("\nThe calendars have promised to include this in a Bitcoin block. That\n")
	fmt.Printf("takes a few hours, and the proof only becomes evidence once it has: run\n")
	fmt.Printf("`norn stamp` again later, or upgrade the file with the `ots` tool, to\n")
	fmt.Printf("replace the pending branches with block attestations.\n")
	return nil
}
