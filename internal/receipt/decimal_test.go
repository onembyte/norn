package receipt

import (
	"testing"
	"time"
)

// D-076 gives every decimal note line the same inclusive signed integer bound.
// Check it with and without a clock so expiry cannot hide a malformed deadline.
func TestADeadlineFitsTheSignedIntegerBound(t *testing.T) {
	k := key(t)
	leaf := leafHash(t, "an entry")
	keys := []string{vkey(t, k, origin)}
	for _, now := range []time.Time{{}, time.Unix(1_760_000_000, 0)} {
		for _, deadline := range []uint64{1<<63 - 1, 1 << 63} {
			raw := signed(t, k, origin, origin, leaf, deadline)
			got, err := Check(raw, keys, origin, leaf, now)
			if deadline == 1<<63-1 {
				if err != nil || got.Deadline != deadline {
					t.Fatalf("the inclusive bound was refused: %v", err)
				}
			} else if code, _ := CodeOf(err); code != Deadline {
				t.Errorf("deadline %d with clock %v: got %q (%v), want deadline", deadline, now, code, err)
			}
		}
	}
}
