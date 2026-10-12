package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/onembyte/norn/internal/entry"
)

// applyPrevFlag applies -prev (SPEC §4.4). On a fresh entry it chooses the
// version the signature assumes. On an entry being extended it may only
// confirm it: `prev` is inside the preimage, so changing it would invalidate
// every signature already there, including a predecessor another signer
// approved.
func applyPrevFlag(env *entry.Envelope, fresh bool, value int64, given bool) error {
	if !given {
		return nil
	}
	if !fresh {
		if env.Prev == nil || *env.Prev != uint64(value) {
			return errors.New("the entry's prev guard does not match the given flag; existing signed fields cannot be changed")
		}
		return nil
	}
	n := uint64(value)
	env.Prev = &n
	return nil
}

// printPrevSummary is the summary's `prev` line, written beside `after`'s to
// the same writer, so a confirmation on the terminal shows it with the rest.
func printPrevSummary(w io.Writer, env *entry.Envelope) {
	if env.Prev != nil {
		fmt.Fprintf(w, "  prev       %d\n", *env.Prev)
		return
	}
	fmt.Fprintln(w, "  prev       (none — only a first enrolment of an id carries none)")
}
