// Package evrefusal is SPEC §11.1's vocabulary: the closed list of reasons an
// evidence reader gives when it refuses to conclude a fork.
//
// D-061: two conforming readers that refuse the same evidence have to refuse it
// for the same reason, or a vector can only say "rejected" and a reader that
// rejects everything for the wrong reason passes. A code is that reason, named
// once, in the order the reader checks -- so when evidence is wrong in two ways,
// the code is the one whose check comes first.
//
// The package is a leaf. It knows the names and nothing about checkpoints,
// proofs or evidence files, so every package that checks evidence can depend on
// it and it depends on nobody.
package evrefusal

import (
	"errors"
	"fmt"
)

// Code is one of §11.1's reasons.
type Code string

// The evidence reader's ten, in the order `forkevidence.Check` checks them.
const (
	Oversize    Code = "oversize"    // file exceeds MAX_EVIDENCE_BYTES
	Decode      Code = "decode"      // not valid deterministic CBOR / not a map
	Version     Code = "version"     // unsupported evidence version
	Schema      Code = "schema"      // closed-map rule, missing field, wrong type
	Policy      Code = "policy"      // carried policy does not parse
	Held        Code = "held"        // held checkpoint fails §10
	Conflicting Code = "conflicting" // conflicting checkpoint fails §10
	Size        Code = "size"        // size above held's, or conflicting mismatch
	Proof       Code = "proof"       // consistency proof does not chain
	Consistent  Code = "consistent"  // the two roots agree; not a fork
)

var all = []Code{
	Oversize, Decode, Version, Schema, Policy, Held, Conflicting, Size, Proof, Consistent,
}

// All is the list in §11.1's order. It is a copy.
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
		panic(fmt.Sprintf("evrefusal: %q is not a §11.1 code", c))
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
