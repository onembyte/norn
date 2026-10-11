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

// Code is one of §7's closed receipt refusal reasons. The order is the order
// Check evaluates them, so a receipt with multiple faults has one stable answer.
type Code string

const (
	Note          Code = "note"
	LogSignature  Code = "log-signature"
	ReceiptFormat Code = "receipt"
	Origin        Code = "origin"
	LeafHash      Code = "leaf-hash"
	Deadline      Code = "deadline"
	Entry         Code = "entry"
	Expired       Code = "expired"
)

var codes = []Code{Note, LogSignature, ReceiptFormat, Origin, LeafHash, Deadline, Entry, Expired}

// All returns §7's refusal codes in check order. The returned slice is a copy.
func All() []Code { return append([]Code(nil), codes...) }

// Known reports whether c belongs to §7's closed refusal vocabulary.
func Known(c Code) bool {
	for _, known := range codes {
		if c == known {
			return true
		}
	}
	return false
}

// Error is a receipt refusal with its stable reason attached.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// CodeOf returns the outermost receipt refusal code, if err carries one.
func CodeOf(err error) (Code, bool) {
	var refusal *Error
	if errors.As(err, &refusal) {
		return refusal.Code, true
	}
	return "", false
}

func refusalf(code Code, format string, args ...any) error {
	if !Known(code) {
		panic(fmt.Sprintf("receipt: %q is not a §7 receipt code", code))
	}
	return &Error{Code: code, Err: fmt.Errorf("receipt: "+format, args...)}
}

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
	// Note framing precedes trust lookup: malformed signed-note structure is
	// `note`, even when no key could verify it.
	if _, _, err := note.Split(signed); err != nil {
		return nil, refusalf(Note, "malformed signed note: %v", err)
	}
	if len(logKeys) == 0 {
		return nil, refusalf(LogSignature, "no log key to check the signature against")
	}
	text, err := note.Verify(signed, logKeys)
	if err != nil {
		return nil, refusalf(LogSignature, "not signed by a key this anchor trusts: %w", err)
	}

	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 4 {
		return nil, refusalf(ReceiptFormat, "a receipt has 4 lines, this one has %d", len(lines))
	}
	if lines[0] != note.ReceiptHeader {
		return nil, refusalf(ReceiptFormat, "first line is %q, want %q", lines[0], note.ReceiptHeader)
	}
	if lines[1] != origin {
		return nil, refusalf(Origin, "it is for %q, not %q", lines[1], origin)
	}
	hash, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil {
		return nil, refusalf(LeafHash, "the leaf hash is not base64: %w", err)
	}
	if base64.StdEncoding.EncodeToString(hash) != lines[2] {
		return nil, refusalf(LeafHash, "the leaf hash is not canonical base64")
	}
	if len(hash) != 32 {
		return nil, refusalf(LeafHash, "the leaf hash is %d bytes, want 32", len(hash))
	}
	deadline, err := strconv.ParseUint(lines[3], 10, 64)
	if err != nil {
		return nil, refusalf(Deadline, "the deadline is not a unix timestamp: %w", err)
	}
	// D-076 bounds every decimal note line before a signed clock comparison.
	// A larger deadline is malformed, not an expired promise after a cast.
	if deadline > 1<<63-1 {
		return nil, refusalf(Deadline, "the deadline is above 2^63-1")
	}
	// Canonical decimal, exactly as §6's size line: no leading zeroes, no
	// sign. §7 calls a receipt non-repudiable proof of log misbehaviour, which
	// means two parties will one day compare two copies of one -- and a number
	// with two spellings is a comparison with two answers (cold gate run 11,
	// D4). `ParseUint` alone accepts `00123`.
	if lines[3] != strconv.FormatUint(deadline, 10) {
		return nil, refusalf(Deadline, "the deadline %q is not canonical decimal", lines[3])
	}

	if leaf != nil && string(leaf) != string(hash) {
		return nil, refusalf(Entry, "it promises a different entry than the one submitted")
	}
	// Compared as signed. `now.Unix()` is negative before 1970 and the zero
	// `time.Time` is year 1; casting that to uint64 wrapped it to something
	// enormous, which made every receipt look expired -- silently, and in the
	// direction that turns a valid promise into a refusal.
	if !now.IsZero() && int64(deadline) <= now.Unix() {
		return nil, refusalf(Expired, "the deadline has already passed (%s); a promise "+
			"about the past promises nothing",
			time.Unix(int64(deadline), 0).Format(time.RFC3339))
	}
	return &Receipt{Origin: lines[1], LeafHash: hash, Deadline: deadline, Signed: signed}, nil
}

// ErrExpired reports a deadline that passed before inclusion was seen.
var ErrExpired = errors.New("the log missed its own deadline")
