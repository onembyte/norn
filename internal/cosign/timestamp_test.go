package cosign

import (
	"crypto/ed25519"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
)

// The old cast made an out-of-range field a negative signed decimal. A line
// signed over that wrapped value exposes the missing rule before Ed25519.
func TestAnOversizedTimestampIsRefusedBeforeItsCastAndSignature(t *testing.T) {
	signed, body := signedCheckpoint(t)
	name := "norn-witness/pi"
	private := key(t, name)
	for _, at := range []uint64{1 << 63, ^uint64(0)} {
		for _, message := range [][]byte{Message(time.Unix(int64(at), 0), body), []byte("not the cosigned message")} {
			payload := note.KeyIDFor(name, public(t, private), note.AlgCosignature)
			payload = binary.BigEndian.AppendUint64(payload, at)
			payload = append(payload, ed25519.Sign(private, message)...)
			_, err := Verify(signed+note.SignatureLine(name, payload)+"\n", []string{witnessVerifier(t, name)})
			if code, _ := refusal.CodeOf(err); code != refusal.Cosignature || err == nil || !strings.Contains(err.Error(), "timestamp is above") {
				t.Errorf("timestamp %d must fail the bound before signature verification: %v", at, err)
			}
		}
	}
	line, err := Sign(body, name, private, time.Unix(1<<63-1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signed+line+"\n", []string{witnessVerifier(t, name)}); err != nil {
		t.Fatalf("the bound itself must verify: %v", err)
	}
}
