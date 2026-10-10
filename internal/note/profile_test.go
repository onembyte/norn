package note

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// D-074 (c), as corrected 2026-10-10: framing is every line's -- canonical
// base64 and a key id -- and length is the matched key's to judge. A line
// whose name and key id match no trusted key is ignored whatever its length:
// a shared log may carry a cosignature on an algorithm nobody here knows, and
// refusing the note over it would stop a Norn reader accepting checkpoints
// every other reader accepts (§10). Until this, Split refused every line that
// was not 68 or 76 bytes, trusted or not.
func TestALineFromAKeyNobodyHoldsIsIgnoredWhateverItsLength(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	signed, err := Sign("a.example\n1\nAAAA\n", "a.example", key)
	if err != nil {
		t.Fatal(err)
	}
	vkey := VerifierKey("a.example", key.Public().(ed25519.PublicKey))
	for _, length := range []int{4, 70, 100} {
		stranger := SignatureLine("witness.elsewhere", make([]byte, length)) + "\n"
		if _, err := Verify(signed+stranger, []string{vkey}); err != nil {
			t.Errorf("a %d-byte line from a key nobody holds broke the note: %v", length, err)
		}
	}
	// Framing still applies to it: no key id, or not base64, is malformed.
	for _, bad := range []string{
		SigPrefix + "witness.elsewhere " + base64.StdEncoding.EncodeToString([]byte{1, 2, 3}) + "\n",
		SigPrefix + "witness.elsewhere not-base64\n",
	} {
		if _, err := Verify(signed+bad, []string{vkey}); err == nil {
			t.Errorf("a stranger's line without framing was ignored: %q", bad)
		}
	}
	// And the matched key still judges its own line: one byte too many is
	// refused, however the strangers fare.
	lines := strings.Split(strings.TrimSuffix(signed, "\n"), "\n")
	last := lines[len(lines)-1]
	payload, err := base64.StdEncoding.DecodeString(last[strings.LastIndex(last, " ")+1:])
	if err != nil {
		t.Fatal(err)
	}
	lines[len(lines)-1] = SignatureLine("a.example", append(payload, 0))
	if _, err := Verify(strings.Join(lines, "\n")+"\n", []string{vkey}); err == nil {
		t.Error("the trusted key's own line with one byte too many verified")
	}
}

// D-074 (c): the signed text and every signature line are UTF-8, and a note
// that is not is malformed.
func TestANoteThatIsNotUTF8IsMalformed(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	vkey := VerifierKey("a.example", key.Public().(ed25519.PublicKey))
	text, err := Sign("caf\xe9\n1\nAAAA\n", "a.example", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Split(text); err == nil {
		t.Error("a note whose text is not UTF-8 split")
	}
	signed, err := Sign("a.example\n1\nAAAA\n", "a.example", key)
	if err != nil {
		t.Fatal(err)
	}
	stranger := SignatureLine("witness.\xff", make([]byte, 68)) + "\n"
	if _, _, err := Split(signed + stranger); err == nil {
		t.Error("a signature line whose name is not UTF-8 split")
	}
	if _, err := Verify(signed+stranger, []string{vkey}); err == nil {
		t.Error("a note with a non-UTF-8 signature line verified")
	}
}
