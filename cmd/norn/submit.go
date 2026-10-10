package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/receipt"
	"github.com/onembyte/norn/internal/trust"
)

func submitCmd(args []string) error {
	fs := newFlagSet("submit")
	trustPath := fs.String("trust", "", "path to norn.trust (required)")
	logLocation := fs.String("log", "", "log URL; defaults to the anchor's first log_urls entry")
	receiptPath := fs.String("receipt", "", "where to keep the receipt (default: <entry>.receipt)")
	wait := fs.Bool("wait", false, "wait until the entry is included, or the deadline passes")
	poll := fs.Duration("poll", 2*time.Second, "how often to check for inclusion while waiting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *trustPath == "" {
		fs.Usage()
		return errors.New("-trust is required: a receipt is only meaningful under an anchor")
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("give exactly one entry file")
	}

	anchor, err := loadAnchor(*trustPath)
	if err != nil {
		return err
	}
	entryPath := fs.Arg(0)
	raw, err := os.ReadFile(entryPath)
	if err != nil {
		return err
	}
	// Refuse to send what this machine can already see is not an entry.
	env, err := entry.Decode(raw)
	if err != nil {
		return fmt.Errorf("that file is not a well-formed entry: %w", err)
	}
	if string(env.Net) != string(anchor.Net) {
		return errors.New("that entry is for another network")
	}

	base := *logLocation
	if base == "" {
		if len(anchor.LogURLs) == 0 {
			return errors.New("the anchor lists no log_urls; pass -log")
		}
		base = anchor.LogURLs[0]
	}

	signed, status, err := logclient.Submit(base, raw)
	if err != nil {
		return err
	}
	if err := submissionError(status, signed); err != nil {
		return err
	}

	leaf := entry.LeafHash(raw)
	got, err := receipt.Check(signed, []string{anchor.LogKey}, anchor.Origin, leaf, time.Now())
	if err != nil {
		return fmt.Errorf("the log answered, but its receipt is not usable: %w", err)
	}

	// §7: keep the receipt until inclusion is verified. Writing it before
	// waiting matters -- if this process dies mid-wait, the evidence survives.
	stored := *receiptPath
	if stored == "" {
		stored = entryPath + ".receipt"
	}
	if err := os.WriteFile(stored, []byte(got.Signed), 0o644); err != nil {
		return fmt.Errorf("keeping the receipt: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Submitted to %s\n", base)
	fmt.Fprintf(os.Stderr, "  entry hash %x\n", entry.EntryHash(raw))
	fmt.Fprintf(os.Stderr, "  receipt    %s\n", stored)
	fmt.Fprintf(os.Stderr, "  deadline   %s  (the log promises inclusion by then)\n",
		got.DeadlineTime().Format(time.RFC3339))

	if !*wait {
		fmt.Fprintf(os.Stderr, "\nKeep that receipt until you have verified inclusion: a leaf "+
			"missing from\nevery checkpoint after the deadline is proof the log misbehaved "+
			"(§7).\n")
		return nil
	}
	return waitForInclusion(anchor, base, leaf, got, *poll)
}

// submissionError turns §7's status codes into something a person can act on.
func submissionError(status int, body string) error {
	trimmed := strings.TrimSpace(body)
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusConflict:
		// Advisory by §6: the log's own replay refused it. Worth acting on,
		// but it is the log's opinion, not a verdict a verifier would share.
		return fmt.Errorf("the log's own replay rejected the entry (advisory, §6): %s", trimmed)
	case http.StatusBadRequest:
		return fmt.Errorf("the log calls the submission malformed: %s", trimmed)
	case http.StatusTooManyRequests:
		return fmt.Errorf("the log is rate-limiting submissions; try again later")
	default:
		return fmt.Errorf("the log answered %d: %s", status, trimmed)
	}
}

// waitForInclusion polls until the leaf is in a verified checkpoint, or the
// log misses the deadline it signed.
func waitForInclusion(anchor *trust.Trust, base string, leaf []byte,
	promise *receipt.Receipt, poll time.Duration) error {

	fetcher, err := logclient.Open(base)
	if err != nil {
		return err
	}
	for {
		index, size, err := findLeaf(fetcher, anchor, leaf)
		if err == nil {
			fmt.Fprintf(os.Stderr, "\nIncluded at index %d of a verified checkpoint of "+
				"size %d.\n", index, size)
			return nil
		}
		if !errors.Is(err, errNotIncluded) {
			return err
		}
		if time.Now().After(promise.DeadlineTime()) {
			return fmt.Errorf("%w: the deadline was %s and the leaf is still absent.\n"+
				"That receipt is now evidence (THREAT-MODEL A2) — keep it",
				receipt.ErrExpired, promise.DeadlineTime().Format(time.RFC3339))
		}
		time.Sleep(poll)
	}
}

var errNotIncluded = errors.New("not included yet")

// findLeaf verifies the log and looks for the leaf in it. Verifying every time
// is the point: inclusion in a log that no longer checks out is not inclusion.
func findLeaf(f logclient.Fetcher, anchor *trust.Trust, leaf []byte) (index int64, size int64, err error) {
	result, err := logclient.Verify(f, anchorFor(anchor))
	if errors.Is(err, logclient.ErrEmptyLog) {
		// A log that has published nothing has not included this entry yet --
		// the genesis, when this is the network's first submission -- and the
		// deadline in its receipt still bounds the wait (D-074 (g)).
		return 0, 0, errNotIncluded
	}
	if err != nil {
		return 0, 0, err
	}
	for i, raw := range result.Served {
		if string(entry.LeafHash(raw)) == string(leaf) {
			return int64(i), result.Checkpoint.Size, nil
		}
	}
	return 0, result.Checkpoint.Size, errNotIncluded
}
