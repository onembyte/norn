package evrefusal

import (
	"errors"
	"fmt"
	"testing"
)

// The vocabulary is SPEC §11.1's, and the order is the order the evidence
// reader checks in: format first, then the two checkpoints, then size, proof
// and the fork conclusion.

func TestAllIsTheClosedListInPrecedenceOrder(t *testing.T) {
	want := []Code{
		Oversize, CBOR, Version, Schema, Policy, Held, Conflicting, Size, Proof, Consistent,
	}
	got := All()
	if len(got) != len(want) {
		t.Fatalf("%d codes, want %d", len(got), len(want))
	}
	seen := map[Code]bool{}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("code %d is %q, want %q", i, got[i], want[i])
		}
		if seen[got[i]] {
			t.Errorf("%q appears twice", got[i])
		}
		seen[got[i]] = true
	}
	// All hands out a copy: a caller cannot reorder the vocabulary for
	// everyone else.
	got[0] = "tampered"
	if All()[0] != Oversize {
		t.Error("All returns the package's own slice, so a caller can change the list")
	}
}

func TestACodeSurvivesWrappingAndTheErrorChainIsKept(t *testing.T) {
	sentinel := errors.New("evidence error")
	inner := fmt.Errorf("%w: the held checkpoint is for another origin", sentinel)
	err := Wrap(Held, inner)

	code, ok := CodeOf(err)
	if !ok || code != Held {
		t.Fatalf("CodeOf = %q, %v; want %q, true", code, ok, Held)
	}
	// Every contract the reader's callers already rely on has to survive:
	// a code is added to an error, never substituted for it.
	if !errors.Is(err, sentinel) {
		t.Error("errors.Is no longer finds the sentinel through the wrapper")
	}
	if err.Error() != inner.Error() {
		t.Errorf("the message changed to %q; the code is metadata, not text", err.Error())
	}

	// Further wrapping by a caller that keeps the chain (%w) keeps the code.
	outer := fmt.Errorf("verifying: %w", err)
	if code, _ := CodeOf(outer); code != Held {
		t.Errorf("a %%w wrap lost the code: got %q", code)
	}
}

func TestErrorsAsReachesATypedErrorInsideTheWrapper(t *testing.T) {
	type evidenceLike struct{ error }
	inner := &evidenceLike{errors.New("the branches disagree")}
	err := Wrap(Consistent, inner)
	var target *evidenceLike
	if !errors.As(err, &target) {
		t.Error("errors.As cannot reach a typed error inside the wrapper; " +
			"callers relying on *ForkError would stop being detectable")
	}
}

// The outermost code decides. A refusal is reported once, at the step that
// made it; a caller that re-coded an already-coded error would be reporting
// a different step than the one that failed.
func TestTheOutermostCodeDecides(t *testing.T) {
	err := Wrap(Size, Wrap(Proof, errors.New("x")))
	if code, _ := CodeOf(err); code != Size {
		t.Errorf("CodeOf = %q, want the outermost, %q", code, Size)
	}
}

func TestAnUncodedErrorHasNoCode(t *testing.T) {
	for _, err := range []error{nil, errors.New("plain")} {
		if code, ok := CodeOf(err); ok || code != "" {
			t.Errorf("CodeOf(%v) = %q, %v; want \"\", false", err, code, ok)
		}
	}
}

func TestWrappingNilIsNil(t *testing.T) {
	// So a caller can write `return evrefusal.Wrap(evrefusal.Policy, check())`
	// without a branch, and success stays success.
	if err := Wrap(Policy, nil); err != nil {
		t.Errorf("Wrap(Policy, nil) = %v, want nil", err)
	}
}

// The list is closed. A code outside it is a programming error in this
// repository, not a runtime condition, so it fails loudly at the call site.
func TestACodeOutsideTheListIsRefused(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Wrap accepted a code that is not in §11.1's list")
		}
	}()
	_ = Wrap(Code("made-up"), errors.New("x"))
}

func TestKnownMatchesTheList(t *testing.T) {
	for _, c := range All() {
		if !Known(c) {
			t.Errorf("%q is in All and Known says no", c)
		}
	}
	for _, c := range []Code{"", "quorum", "fork", "made-up"} {
		if Known(c) {
			t.Errorf("Known(%q) = true; it is not an evidence refusal code", c)
		}
	}
}

// A layer that restates a lower layer's refusal in its own words keeps the
// lower layer's reason: the words change, the code does not. A cause with no
// code -- a configuration fault -- gives none.
func TestCarryKeepsTheCausesCodeAndNothingElse(t *testing.T) {
	cause := Wrap(Policy, errors.New("no valid policy"))
	restated := errors.New("evidence check error: no valid policy")

	err := Carry(cause, restated)
	if code, _ := CodeOf(err); code != Policy {
		t.Errorf("CodeOf = %q, want the cause's %q", code, Policy)
	}
	if err.Error() != restated.Error() {
		t.Errorf("the message is %q; the restatement is the caller's to choose", err.Error())
	}
	if !errors.Is(err, restated) {
		t.Error("the restated error is no longer on the chain")
	}

	plain := Carry(errors.New("witness key: malformed"), restated)
	if code, ok := CodeOf(plain); ok {
		t.Errorf("an uncoded cause gave the restatement the code %q", code)
	}
	if plain != restated {
		t.Error("with nothing to carry, the restatement should come back as it is")
	}
}
