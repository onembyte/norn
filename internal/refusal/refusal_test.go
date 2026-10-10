package refusal

import (
	"errors"
	"fmt"
	"testing"
)

// The vocabulary is SPEC §10.1's, and the order is the order the verifier
// checks in: the loop's thirteen, then the bundle check's three. The specdoc
// package compares All against §10.1's table, so this list and the document
// cannot drift apart.

func TestAllIsTheClosedListInPrecedenceOrder(t *testing.T) {
	want := []Code{
		Unserved, Note, LogSignature, Checkpoint, Origin, Cosignature,
		Quorum, Entries, Head, Fork, Rollback, Genesis, Tiles,
		Bundle, Inclusion, Binding,
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
	if All()[0] != Unserved {
		t.Error("All returns the package's own slice, so a caller can change the list")
	}
}

func TestACodeSurvivesWrappingAndTheErrorChainIsKept(t *testing.T) {
	sentinel := errors.New("log error")
	inner := fmt.Errorf("%w: the checkpoint is for another origin", sentinel)
	err := Wrap(Origin, inner)

	code, ok := CodeOf(err)
	if !ok || code != Origin {
		t.Fatalf("CodeOf = %q, %v; want %q, true", code, ok, Origin)
	}
	// Every contract the verifier's callers already rely on has to survive:
	// a code is added to an error, never substituted for it.
	if !errors.Is(err, sentinel) {
		t.Error("errors.Is no longer finds the sentinel through the wrapper")
	}
	if err.Error() != inner.Error() {
		t.Errorf("the message changed to %q; the code is metadata, not text", err.Error())
	}

	// Further wrapping by a caller that keeps the chain (%w) keeps the code.
	outer := fmt.Errorf("verifying: %w", err)
	if code, _ := CodeOf(outer); code != Origin {
		t.Errorf("a %%w wrap lost the code: got %q", code)
	}
}

func TestErrorsAsReachesATypedErrorInsideTheWrapper(t *testing.T) {
	type forkLike struct{ error }
	inner := &forkLike{errors.New("the branches disagree")}
	err := Wrap(Fork, inner)
	var target *forkLike
	if !errors.As(err, &target) {
		t.Error("errors.As cannot reach a typed error inside the wrapper; " +
			"logclient's *ForkError would stop being detectable")
	}
}

// The outermost code decides. A refusal is reported once, at the step that
// made it; a caller that re-coded an already-coded error would be reporting
// a different step than the one that failed.
func TestTheOutermostCodeDecides(t *testing.T) {
	err := Wrap(Entries, Wrap(Head, errors.New("x")))
	if code, _ := CodeOf(err); code != Entries {
		t.Errorf("CodeOf = %q, want the outermost, %q", code, Entries)
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
	// So a caller can write `return refusal.Wrap(refusal.Quorum, check())`
	// without a branch, and success stays success.
	if err := Wrap(Quorum, nil); err != nil {
		t.Errorf("Wrap(Quorum, nil) = %v, want nil", err)
	}
}

// The list is closed. A code outside it is a programming error in this
// repository, not a runtime condition, so it fails loudly at the call site.
func TestACodeOutsideTheListIsRefused(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Wrap accepted a code that is not in §10.1's list")
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
	for _, c := range []Code{"", "decode", "threshold", "made-up"} {
		if Known(c) {
			t.Errorf("Known(%q) = true; it is not a verifier refusal code", c)
		}
	}
}

// A layer that restates a lower layer's refusal in its own words keeps the
// lower layer's reason: the words change, the code does not. A cause with no
// code -- a configuration fault -- gives none.
func TestCarryKeepsTheCausesCodeAndNothingElse(t *testing.T) {
	cause := Wrap(LogSignature, errors.New("no valid signature from a trusted key"))
	restated := errors.New("proof bundle error: checkpoint: no valid signature from a trusted key")

	err := Carry(cause, restated)
	if code, _ := CodeOf(err); code != LogSignature {
		t.Errorf("CodeOf = %q, want the cause's %q", code, LogSignature)
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
