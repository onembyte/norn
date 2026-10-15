package replay

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/state"
)

// These answers come from §5.1 and §5.2, independently of the manifest.
func TestEveryRepublishCaseMatchesAndRepairsItsNamedFault(t *testing.T) {
	names := []string{"00-genesis", "01-enroll-nas", "02-revoke-stripped", "03-revoke-genuine", "04-note-preimage", "05-note-genuine", "06-copy-applied-extra-sig", "07-copy-refused-bytes", "08-log-key-anchor", "09-log-key-new", "10-log-key-learned", "11-policy-name-not-ascii", "12-policy-name-ascii"}
	codes := []string{"", "", ReasonThreshold, "", ReasonDecode, "", ReasonDupEntry, ReasonDupEntry, ReasonDupKey, "", ReasonDupKey, ReasonDecode, ""}
	dir := vectorRoot() + "/log-republish"
	anchor, raw, m := loadCase(t, dir)
	if len(raw) != len(names) {
		t.Fatalf("got %d entries, want %d", len(raw), len(names))
	}
	final := Replay(anchor, raw)
	for i, name := range names {
		t.Run(name, func(t *testing.T) {
			if m.Entries[i].Name != name || m.Entries[i].Reason != codes[i] {
				t.Fatal("manifest differs from the stated answer")
			}
			if got := lastOutcome(final, i); got != codes[i] {
				t.Fatalf("Go = %q, want %q", got, codes[i])
			}
			t.Logf("Go = %q", codes[i])
			if codes[i] != "" {
				before, after := Replay(anchor, raw[:i]), Replay(anchor, raw[:i+1])
				after.Size, after.Rejected = before.Size, before.Rejected
				a, err := after.MarshalCanonical()
				if err != nil {
					t.Fatal(err)
				}
				b, err := before.MarshalCanonical()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(a, b) {
					t.Fatal("refusal changed state")
				}
			}
			check := func(prefix [][]byte, repaired []byte, want string) {
				t.Helper()
				if got := lastOutcome(Replay(anchor, append(append([][]byte(nil), prefix...), repaired)), len(prefix)); got != want {
					t.Fatalf("repair Go = %q, want %q", got, want)
				}
			}
			switch i {
			case 2:
				e, err := entry.Decode(raw[i])
				if err != nil {
					t.Fatal(err)
				}
				if err := entry.Sign(e, privateKey(t, "signer1"), "signer"); err != nil {
					t.Fatal(err)
				}
				repaired, err := entry.Encode(e)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(repaired, raw[3]) {
					t.Fatal("genuine revoke changes more than signatures")
				}
				check(raw[:i], repaired, "")
			case 3, 5:
				// The genuine entry still applies when the preceding refused bytes never
				// arrived. Its after value allows that earlier append position too.
				check(raw[:i-1], raw[i], "")
			case 4:
				e, err := entry.Decode(raw[5])
				if err != nil {
					t.Fatal(err)
				}
				pre, err := entry.Preimage(e)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(pre, raw[i]) {
					t.Fatal("not the genuine note's preimage")
				}
				check(raw[:i], raw[5], "")
			case 6:
				e, err := entry.Decode(raw[i])
				if err != nil {
					t.Fatal(err)
				}
				original, err := entry.Decode(raw[5])
				if err != nil {
					t.Fatal(err)
				}
				if len(e.Sigs) != len(original.Sigs)+1 || e.Sigs[len(e.Sigs)-1].Kid != "ffffffffffffffff" {
					t.Fatal("copy needs exactly one sorted unresolvable signature")
				}
				e.Sigs = e.Sigs[:len(e.Sigs)-1]
				encoded, err := entry.Encode(e)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(encoded, raw[5]) {
					t.Fatal("copy differs in more than its signature list")
				}
				check(raw[:5], raw[i], "")
			case 7:
				if !bytes.Equal(raw[i], raw[2]) {
					t.Fatal("not a byte copy of the refusal")
				}
				// Isolate the byte set before the genuine revoke applies: without the
				// first copy this is threshold; repairing only its signatures accepts.
				check(raw[:3], raw[i], ReasonDupEntry)
				check(raw[:2], raw[i], ReasonThreshold)
				check(raw[:3], raw[3], "")
			case 8, 10, 11:
				e, err := entry.Decode(raw[i])
				if err != nil {
					t.Fatal(err)
				}
				if i == 11 {
					e.Body["text"] = strings.ReplaceAll(e.Body["text"].(string), "zürich", "zurich")
				} else {
					e.Body["pk"] = publicOf(t, "logkey3")
				}
				e.Sigs = nil
				for _, key := range []string{"root1", "root2"} {
					if err := entry.Sign(e, privateKey(t, key), "root"); err != nil {
						t.Fatal(err)
					}
				}
				repaired, err := entry.Encode(e)
				if err != nil {
					t.Fatal(err)
				}
				check(raw[:i], repaired, "")
			}
		})
	}
	if final.Devices["nas"].Status != state.StatusRevoked {
		t.Fatal("genuine revoke did not revoke nas")
	}
	want, err := os.ReadFile(dir + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := final.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("republish state differs from state.json")
	}
}
