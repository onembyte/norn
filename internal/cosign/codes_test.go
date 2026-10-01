package cosign

import (
	"errors"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
)

// Verify is §10.1's step 6, and it names it: a listed witness's line that does
// not verify is refused as `cosignature` (D-061). The quorum, step 7, is the
// caller's -- this package does not know the policy's thresholds.
//
// What is not the checkpoint's fault carries no code: a witness key that does
// not parse, or that is a plain note key, is the policy's mistake, and the
// policy is the anchor. It is reported before the note is read, whatever state
// the note is in, as tlog.Verify reports a malformed log key.

func TestAForgedCosignatureIsACosignatureRefusal(t *testing.T) {
	signed, body := signedCheckpoint(t)
	name := "norn-witness/pi"
	line, err := Sign(body, name, key(t, "impostor"), time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	forged := forgeKeyID(t, line, name, public(t, key(t, name)))

	_, err = Verify(signed+forged+"\n", []string{witnessVerifier(t, name)})
	if code, _ := refusal.CodeOf(err); code != refusal.Cosignature {
		t.Errorf("refused as %q, want %q (%v)", code, refusal.Cosignature, err)
	}
	if !errors.Is(err, ErrCosign) {
		t.Errorf("%v is no longer ErrCosign", err)
	}
}

func TestANoteThatDoesNotFrameIsANoteRefusal(t *testing.T) {
	_, err := Verify("origin\n1\nroot\n", []string{witnessVerifier(t, "norn-witness/pi")})
	if code, _ := refusal.CodeOf(err); code != refusal.Note {
		t.Errorf("refused as %q, want %q (%v)", code, refusal.Note, err)
	}
}

func TestABadWitnessKeyIsTheAnchorsFaultNotTheCheckpoints(t *testing.T) {
	signed, _ := signedCheckpoint(t)
	plain := note.VerifierKey("norn-witness/pi", public(t, key(t, "norn-witness/pi")))
	for _, keys := range [][]string{{plain}, {"not a verifier key"}} {
		for _, input := range []string{signed, "not a note"} {
			_, err := Verify(input, keys)
			if err == nil {
				t.Fatalf("witness keys %q were accepted", keys)
			}
			if code, ok := refusal.CodeOf(err); ok {
				t.Errorf("a configuration error was reported as the checkpoint's %q: %v", code, err)
			}
			if !errors.Is(err, ErrCosign) {
				t.Errorf("%v is no longer ErrCosign", err)
			}
		}
	}
}
