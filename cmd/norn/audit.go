package main

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/plainlog"
)

// auditCmd answers the question a revoked key cannot: **what did they do with
// it?**
//
// `ENROLLMENT.md` R2 makes this step one of recovering from a stolen signer
// key, before the `signer_remove` and before any `revoke`. Removing the key
// stops the next thing; this finds the last things — and a transparency log is
// the only reason the answer exists at all. A control plane with an admin
// console can tell you the current state; it cannot tell you what a key did
// three weeks ago, because nothing kept the receipts.
func auditCmd(args []string) error {
	fs := newFlagSet("audit")
	trustPath := fs.String("trust", "", "path to norn.trust (required)")
	logLocation := fs.String("log", "", "log URL or directory; defaults to the anchor's first log_urls entry")
	by := fs.String("by", "", "the `key id` to audit, as entries carry it (16 hex characters)")
	since := fs.String("since", "", "only entries stamped at or after this RFC 3339 `time`")
	all := fs.Bool("all", false, "include entries the log carried that replay refused")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *trustPath == "" {
		fs.Usage()
		return fmt.Errorf("-trust is required")
	}
	if *by == "" {
		fs.Usage()
		return fmt.Errorf("-by is required: name the key id to audit")
	}
	// A malformed key id must not silently match nothing. "This key signed
	// nothing" is the most dangerous wrong answer this command can give, and a
	// typo would produce it every time.
	if raw, err := hex.DecodeString(*by); err != nil || len(raw) != 8 {
		return fmt.Errorf("%q is not a key id: entries carry one as 16 hex "+
			"characters (SPEC §4.0), and a typo here would report that the key "+
			"signed nothing", *by)
	}

	var after time.Time
	if *since != "" {
		parsed, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("-since: %w", err)
		}
		after = parsed
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

	refused := map[uint64]string{}
	for _, r := range result.State.Rejected {
		refused[r.Index] = r.Reason
	}

	fmt.Printf("network    %s\n", anchor.Name)
	fmt.Printf("auditing   key id %s across %d entries\n\n", *by, result.Checkpoint.Size)
	if !after.IsZero() {
		fmt.Printf("Showing entries stamped at or after %s. Note that `ts` is set by\n",
			after.UTC().Format(time.RFC3339))
		fmt.Printf("whoever signed the entry: if this key was stolen, the thief controls\n")
		fmt.Printf("that field and can place an entry outside this window. Run without\n")
		fmt.Printf("-since to see everything.\n\n")
	}

	found := 0
	for index, raw := range result.Served {
		env, err := entry.Decode(raw)
		if err != nil {
			continue
		}
		if !signedBy(env, *by) {
			continue
		}
		reason, wasRefused := refused[uint64(index)]
		if wasRefused && !*all {
			continue
		}
		if !after.IsZero() && int64(env.TS) < after.Unix() {
			continue
		}
		found++

		stamp := time.Unix(int64(env.TS), 0).UTC().Format(time.RFC3339)
		fmt.Printf("entry %-4d %s  %s\n", index, stamp, plainlog.Describe(env))
		if wasRefused {
			fmt.Printf("           ^ rejected at replay (%s) — it is in the log, and it "+
				"changed nothing\n", reason)
		}
	}

	if found == 0 {
		fmt.Printf("This key signed nothing in this log.\n")
		if !*all {
			fmt.Printf("Entries the log carried but replay refused are hidden; add -all " +
				"to see them.\n")
		}
		return nil
	}
	fmt.Printf("\n%d entr%s signed by %s.\n", found, plural(found), *by)
	if !*all {
		fmt.Printf("Entries replay refused are hidden; add -all to see attempts that " +
			"changed nothing.\n")
	}
	return nil
}

// signedBy reports whether one of an entry's signatures carries this key id.
func signedBy(env *entry.Envelope, kid string) bool {
	for _, sig := range env.Sigs {
		if sig.Kid == kid {
			return true
		}
	}
	return false
}

func plural(n int) string {
	if n == 1 {
		return "y is"
	}
	return "ies are"
}
