// Package receipt checks what a log hands back for a submission (SPEC §7).
//
// A receipt is a promise: *this leaf will be in a checkpoint issued no later
// than `deadline`*. That promise is only worth keeping if it is about the entry
// that was actually submitted, so every check here exists to stop a receipt
// meaning something adjacent to what the submitter thinks it means -- a receipt
// for another leaf, for another log, or one that expired before it arrived.
//
// A receipt whose leaf is absent from every checkpoint cosigned after its
// deadline is non-repudiable proof of log misbehaviour (THREAT-MODEL A2), which
// is why a submitter keeps it until inclusion is verified, and why a receipt
// that does not bind the submitted entry is worse than none: it would be
// evidence about somebody else's entry.
package receipt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/note"
)

// Receipt is the promise a log made.
type Receipt struct {
	Origin   string
	LeafHash []byte
	Deadline uint64
	// Signed is the note as it arrived, which is the evidence itself. Keep it.
	Signed string
}

// Deadline as a time, for printing and for waiting on.
func (r *Receipt) DeadlineTime() time.Time { return time.Unix(int64(r.Deadline), 0) }

func receiptErrorf(format string, args ...any) error {
	return fmt.Errorf("receipt: "+format, args...)
}

// Check verifies a receipt under the log's keys and binds it to one entry.
//
// `leaf` is the leaf hash of the entry that was submitted. Passing nil skips
// that binding, which is only correct when the caller has no entry in hand --
// reading a stored receipt for inspection, say -- and never when submitting.
//
// A zero `now` skips the deadline check, for a caller that has no clock it
// trusts for the purpose. The monitor is one: §7 judges a missed deadline
// against **witness time**, not against whatever the machine holding the
// receipt happens to think.
func Check(signed string, logKeys []string, origin string, leaf []byte, now time.Time) (*Receipt, error) {
	if len(logKeys) == 0 {
		return nil, receiptErrorf("no log key to check the signature against")
	}
	text, err := note.Verify(signed, logKeys)
	if err != nil {
		return nil, receiptErrorf("not signed by a key this anchor trusts: %w", err)
	}

	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 4 {
		return nil, receiptErrorf("a receipt has 4 lines, this one has %d", len(lines))
	}
	if lines[0] != note.ReceiptHeader {
		return nil, receiptErrorf("first line is %q, want %q", lines[0], note.ReceiptHeader)
	}
	if lines[1] != origin {
		return nil, receiptErrorf("it is for %q, not %q", lines[1], origin)
	}
	hash, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, receiptErrorf("the leaf hash is not base64: %w", err)
	}
	if len(hash) != 32 {
		return nil, receiptErrorf("the leaf hash is %d bytes, want 32", len(hash))
	}
	// Exactly its encoding (§7). StdEncoding skips a CR inside the line and
	// ignores non-zero padding bits, so two lines could decode to one leaf
	// and one promise had two spellings -- the same hazard as the deadline
	// below, one line up (cold gate run 11, the D4 review).
	if base64.StdEncoding.EncodeToString(hash) != lines[2] {
		return nil, receiptErrorf("the leaf hash line %q is not the encoding of the leaf hash", lines[2])
	}
	deadline, err := strconv.ParseUint(lines[3], 10, 64)
	if errors.Is(err, strconv.ErrRange) {
		return nil, receiptErrorf("the deadline %q does not fit in 64 bits", lines[3])
	}
	if err != nil {
		return nil, receiptErrorf("the deadline is not a unix timestamp: %w", err)
	}
	// Canonical decimal, as §6's size line is. ParseUint reads `01760000060`
	// as 1760000060, so without this one promise had two spellings, and two
	// copies of one receipt could differ byte for byte (cold gate run 11, D4).
	if lines[3] != strconv.FormatUint(deadline, 10) {
		return nil, receiptErrorf("the deadline %q is not canonical decimal", lines[3])
	}

	if leaf != nil && string(leaf) != string(hash) {
		return nil, receiptErrorf("it promises a different entry than the one submitted")
	}
	// Compared as signed. `now.Unix()` is negative before 1970 and the zero
	// `time.Time` is year 1; casting that to uint64 wrapped it to something
	// enormous, which made every receipt look expired -- silently, and in the
	// direction that turns a valid promise into a refusal.
	if !now.IsZero() && int64(deadline) <= now.Unix() {
		return nil, receiptErrorf("the deadline has already passed (%s); a promise "+
			"about the past promises nothing",
			time.Unix(int64(deadline), 0).Format(time.RFC3339))
	}
	return &Receipt{Origin: lines[1], LeafHash: hash, Deadline: deadline, Signed: signed}, nil
}

// ErrExpired reports a deadline that passed before inclusion was seen.
var ErrExpired = errors.New("the log missed its own deadline")
