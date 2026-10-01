// Package refusal is SPEC §10.1's vocabulary: the closed list of reasons a
// verifier gives when it refuses a log or a proof bundle.
//
// D-061: two conforming verifiers that refuse the same input have to refuse
// it for the same reason, or a vector can only say "rejected" and a verifier
// that rejects everything for the wrong reason passes. A code is that reason,
// named once, in the order the verifier checks -- so when an input is wrong
// in two ways, the code is the one whose check comes first.
//
// The package is a leaf. It knows the names and nothing about logs, notes or
// bundles, so every package that refuses can depend on it and it depends on
// nobody.
package refusal

import (
	"errors"
	"fmt"
)

// Code is one of §10.1's reasons.
type Code string

// The loop's twelve, in the order `logclient.Verify` checks them.
const (
	Unserved     Code = "unserved"
	Note         Code = "note"
	LogSignature Code = "log-signature"
	Checkpoint   Code = "checkpoint"
	Origin       Code = "origin"
	Cosignature  Code = "cosignature"
	Quorum       Code = "quorum"
	Entries      Code = "entries"
	Head         Code = "head"
	Fork         Code = "fork"
	Rollback     Code = "rollback"
	Tiles        Code = "tiles"
)

// The bundle check's three. Between Bundle and Inclusion it refuses with the
// loop's checkpoint codes, because a bundle carries a checkpoint and that
// checkpoint is checked the same way.
const (
	Bundle    Code = "bundle"
	Inclusion Code = "inclusion"
	Binding   Code = "binding"
)

var all = []Code{
	Unserved, Note, LogSignature, Checkpoint, Origin, Cosignature,
	Quorum, Entries, Head, Fork, Rollback, Tiles,
	Bundle, Inclusion, Binding,
}

// All is the list in §10.1's order. It is a copy.
func All() []Code {
	return append([]Code(nil), all...)
}

// Known reports whether c is on the list.
func Known(c Code) bool {
	for _, k := range all {
		if k == c {
			return true
		}
	}
	return false
}

// Error is a refusal with its reason attached. The message and the chain are
// the wrapped error's: a code is added to an error, never substituted for it,
// so every errors.Is and errors.As a caller already relies on keeps working.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Wrap attaches a code to err. A nil err stays nil, so a check can be wrapped
// without a branch. A code outside the list panics: the list is closed, and a
// code nobody specified is a mistake in this repository, not in its input.
func Wrap(c Code, err error) error {
	if !Known(c) {
		panic(fmt.Sprintf("refusal: %q is not a §10.1 code", c))
	}
	if err == nil {
		return nil
	}
	return &Error{Code: c, Err: err}
}

// CodeOf is the outermost code on err's chain. A refusal is coded once, at the
// step that made it; the outermost code is that step's.
func CodeOf(err error) (Code, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Code, true
	}
	return "", false
}

// Carry gives err the code cause carries, if it carries one. It is for a layer
// that restates a lower layer's refusal in its own words: the words change,
// the reason does not. A cause without a code -- a fault in the caller's
// configuration rather than in the input -- leaves err as it is.
func Carry(cause, err error) error {
	if code, ok := CodeOf(cause); ok {
		return Wrap(code, err)
	}
	return err
}
