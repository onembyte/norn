package replay

import (
	"bytes"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/state"
)

// D-078 (1), cold gate run 15's H2. A copy of an entry with its signatures
// stripped, appended before the genuine one, is refused `threshold`. Under
// D-070 it still recorded its signed content, so the genuine entry -- on time,
// its receipt honoured -- was `dup-entry` and the revoke never applied. A
// refused entry now records only its bytes; the genuine revoke applies.
func TestARefusedCopyDoesNotBurnTheGenuineEntry(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	before := Replay(anchor, entries)
	if before.Devices["printer"].Status != state.StatusActive {
		t.Fatal("the fixture's printer is no longer active; pick another device")
	}
	genuine := &entry.Envelope{V: 1, T: "revoke", Net: anchor.Net, TS: 1790000000,
		Body: map[string]any{"device_id": "printer"}}
	signAs(t, genuine, before, "signer", "signer1", "signer2", "signer3")
	stripped := *genuine
	stripped.Sigs = nil

	log := appended(t, appended(t, entries, &stripped), genuine)
	after := Replay(anchor, log)
	if got := lastOutcome(after, len(entries)); got != ReasonThreshold {
		t.Fatalf("the stripped copy is %q, want %q", got, ReasonThreshold)
	}
	if got := lastOutcome(after, len(entries)+1); got != "" {
		t.Fatalf("the genuine revoke after its stripped copy is %q, want it accepted", got)
	}
	if after.Devices["printer"].Status != state.StatusRevoked {
		t.Fatal("the printer is still active")
	}
}

// D-078 (1), cold gate run 15's H1. An entry's signature preimage is itself a
// byte string anyone can append, and it never decodes, so its `entry_hash` is
// the genuine entry's `content_hash`. One shared seen set refused the genuine
// entry after its own preimage; the two kinds of key are never compared now.
func TestAnEntryAfterItsOwnPreimageIsNotADuplicate(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	before := Replay(anchor, entries)
	note := &entry.Envelope{V: 1, T: "note", Net: anchor.Net, TS: 1790000000,
		Body: map[string]any{"text": "after its own preimage"}}
	signAs(t, note, before, "signer", "signer1", "signer2", "signer3")
	preimage, err := entry.Preimage(note)
	if err != nil {
		t.Fatal(err)
	}
	content := sha256.Sum256(preimage)
	if !bytes.Equal(entry.EntryHash(preimage), content[:]) {
		t.Fatal("the preimage's entry hash is not the note's content hash; the test proves nothing")
	}

	log := append(append([][]byte(nil), entries...), preimage)
	after := Replay(anchor, appended(t, log, note))
	if got := lastOutcome(after, len(entries)); got != ReasonDecode {
		t.Fatalf("the preimage appended as an entry is %q, want %q", got, ReasonDecode)
	}
	if got := lastOutcome(after, len(entries)+1); got != "" {
		t.Fatalf("the note after its own preimage is %q, want it accepted", got)
	}
}

// Entry 0 is applied, so its content is an applied entry's too: a copy of the
// genesis under another signature list is `dup-entry` at step 1, as its byte
// copy `bad-repeat-of-genesis` is, and never reaches step 5's `dup-genesis`.
func TestAReSignedCopyOfTheGenesisIsADuplicate(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	copy := copies(t, entries[0], false)["extra signature"]
	after := Replay(anchor, append(append([][]byte(nil), entries...), copy))
	if got := lastOutcome(after, len(entries)); got != ReasonDupEntry {
		t.Fatalf("a re-signed copy of the genesis is %q, want %q", got, ReasonDupEntry)
	}
}

// A fold resumed from a clone must remember both sets (H4-a, D-078): without
// the bytes a copy of a refused entry is judged again, and without the
// applied content a re-signed copy of an applied entry applies again.
func TestACloneCarriesBothSeenSets(t *testing.T) {
	anchor, entries, m := loadCase(t, filepath.Join(vectorRoot(), "log"))
	fold := New(anchor)
	fold.Apply(entries...)
	refused := -1
	for i, e := range m.Entries {
		if e.Reason != "" && e.Reason != ReasonDupEntry && i > 0 {
			refused = i
			break
		}
	}
	for name, raw := range map[string][]byte{
		"byte copy of a refused entry":       entries[refused],
		"re-signed copy of an applied entry": copies(t, entries[1], false)["extra signature"],
	} {
		t.Run(name, func(t *testing.T) {
			clone := fold.Clone()
			st := clone.Apply(raw)
			if got := lastOutcome(st, len(entries)); got != ReasonDupEntry {
				t.Fatalf("after Clone, a %s is %q, want %q", name, got, ReasonDupEntry)
			}
		})
	}
}
