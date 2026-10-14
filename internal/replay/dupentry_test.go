package replay

import (
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/entry"
)

// copies returns a past entry's content under three different signature
// lists: one unresolvable signature added (sorted last, so the ordering rule
// does not refuse it first), one signature's role relabelled, and -- for an
// entry with a surplus signature -- one dropped. Each is new bytes with the
// original signatures still valid, which is what SEC-001 exploits. Each also
// differs from the fixture's own `bad-copy-*` entries, built the same way,
// or a byte-keyed replay would call these duplicates of those.
func copies(t *testing.T, raw []byte, drop bool) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	decode := func() *entry.Envelope {
		env, err := entry.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	extra := decode()
	extra.Sigs = append(extra.Sigs, entry.Signature{Kid: "fffffffffffffff0", Role: "signer", Sig: make([]byte, 64)})
	relabelled := decode()
	relabelled.Sigs[len(relabelled.Sigs)-1].Role = "device"
	for name, env := range map[string]*entry.Envelope{"extra signature": extra, "role relabelled": relabelled} {
		encoded, err := entry.Encode(env)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = encoded
	}
	if drop {
		dropped := decode()
		dropped.Sigs = dropped.Sigs[1:]
		encoded, err := entry.Encode(dropped)
		if err != nil {
			t.Fatal(err)
		}
		out["surplus signature dropped"] = encoded
	}
	return out
}

// D-070 (audit SEC-001). `sigs` sits outside every signature's preimage, and
// an unresolvable signature is ignored, so a past entry plus one junk
// signature was new bytes with the original signatures still counting: it
// passed a byte-keyed `dup-entry` and applied again. On this log, entry 37
// re-enrolled a device revoked at 39 and entry 28 rolled the quorum back from
// three of three to two of three. Duplicates are now keyed on the signed
// content of an applied entry, so every such copy is `dup-entry` -- before any
// other rule. Every original here was applied; a refused one burns only its
// bytes (D-078, refusedcopy_test.go).
func TestAReSignedCopyOfAnAppliedEntryIsADuplicate(t *testing.T) {
	anchor, entries, m := loadCase(t, filepath.Join(vectorRoot(), "log"))
	indexOf := func(name string) int {
		for i, e := range m.Entries {
			if e.Name == name {
				return i
			}
		}
		t.Fatalf("no entry %s", name)
		return -1
	}
	before := Replay(anchor, entries)
	for _, c := range []struct {
		name string
		drop bool
	}{
		{"37-enroll-spare", false}, {"28-policy", false}, {"35-rotate-nas", false},
		{"16-signer_add-signer3", false}, {"89-two-sig-base", true},
	} {
		for variant, copy := range copies(t, entries[indexOf(c.name)], c.drop) {
			t.Run(c.name+"/"+variant, func(t *testing.T) {
				after := Replay(anchor, append(append([][]byte(nil), entries...), copy))
				last := after.Rejected[len(after.Rejected)-1]
				if last.Index != uint64(len(entries)) || last.Reason != ReasonDupEntry {
					t.Fatalf("the copy was not rejected dup-entry: %+v", last)
				}
				if got, want := after.Devices["spare"].Status, before.Devices["spare"].Status; got != want {
					t.Errorf("spare went from %s to %s", want, got)
				}
				if after.Policy != before.Policy || len(after.Signers) != len(before.Signers) {
					t.Error("the copy changed the policy or the signer set")
				}
			})
		}
	}
}

// The key is the content for an entry that decodes, and the bytes for one
// that does not: a copy of an undecodable entry is still `dup-entry` (the
// existing vector), and a decodable entry's content under new bytes is too.
// A different content under the same signatures is a different entry.
func TestDifferentContentIsNotADuplicate(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	env, err := entry.Decode(entries[70])
	if err != nil {
		t.Fatal(err)
	}
	env.TS++ // the content changes; the signatures no longer verify, which is not this rule
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	after := Replay(anchor, append(append([][]byte(nil), entries...), raw))
	last := after.Rejected[len(after.Rejected)-1]
	if last.Reason == ReasonDupEntry {
		t.Fatal("a different content was called a duplicate")
	}
}
