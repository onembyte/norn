package agent

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/forkevidence"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
)

// A leaked key must not come back while the node is frozen, even when the
// held branch re-enrolled it. Build run 19's history with the fixture keys.
func TestADeviceReenrolledWithTheSameKeyAfterTheSplitStaysOutOfTheFrozenSet(t *testing.T) {
	checkChangedRecordAfterSplit(t, false)
}

// Comparing the keys at the two ends misses the rotation in between: nothing
// written after the split can authorize that key's return (D-083).
func TestADeviceRotatedAwayAndBackAfterTheSplitStaysOutOfTheFrozenSet(t *testing.T) {
	checkChangedRecordAfterSplit(t, true)
}

func checkChangedRecordAfterSplit(t *testing.T, rotate bool) {
	t.Helper()
	a, served := heldServed(t)
	doc := anchor(t)
	sign := func(env *entry.Envelope, names ...string) []byte {
		t.Helper()
		env.Sigs = nil
		for _, name := range names {
			role := "signer"
			if name == "nas" {
				role = "device"
			}
			if err := entry.Sign(env, fixtureKey(t, name), role); err != nil {
				t.Fatal(err)
			}
		}
		raw, err := entry.Encode(env)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	enroll, err := entry.Decode(served.Served[1])
	if err != nil {
		t.Fatal(err)
	}
	request, err := enrollreq.Decode(enroll.Body["request"].([]byte))
	if err != nil {
		t.Fatal(err)
	}
	request.TS = 1_760_099_990
	if err := enrollreq.Sign(request, fixtureKey(t, "nas")); err != nil {
		t.Fatal(err)
	}
	rawRequest, err := enrollreq.Encode(request)
	if err != nil {
		t.Fatal(err)
	}
	enroll.TS, enroll.Body = 1_760_100_000, map[string]any{"request": rawRequest}
	firstEnroll := sign(enroll, "signer1", "signer2")
	otherKey, err := hex.DecodeString("2a955fd268cf9d55ba383ba35237a3f626b5141ac92089ccb915e17b86bde82f")
	if err != nil {
		t.Fatal(err)
	}

	// The two-entry prefix is the reader's exact shape. Extending it with
	// the fixture's laptop also proves that an unchanged peer survives.
	for _, split := range []int64{2, 3} {
		name := "reader's two-entry prefix"
		if split == 3 {
			name = "with an unchanged laptop"
		}
		t.Run(name, func(t *testing.T) {
			entries := append([][]byte(nil), served.Served[:split]...)
			entries[1] = firstEnroll
			prev, after := uint64(1), uint64(split)
			change := &entry.Envelope{V: entry.Version, T: "revoke", Net: doc.Net,
				TS: 1_760_100_001, Prev: &prev, After: &after, Body: map[string]any{"device_id": "nas"}}
			if rotate {
				change.T = "rotate"
				change.Body["wg_pk"] = otherKey
				entries = append(entries, sign(change, "nas"))
			} else {
				entries = append(entries, sign(change, "signer1", "signer2"))
			}
			prev, after = uint64(split), uint64(split+1)
			change.TS = 1_760_100_002
			if rotate {
				change.Body["wg_pk"] = request.WGPK
				entries = append(entries, sign(change, "nas"))
			} else {
				reenroll := *request
				reenroll.TS, reenroll.Labels = 1_760_100_002, map[string]string{"ip": "10.7.0.0/16"}
				if err := enrollreq.Sign(&reenroll, fixtureKey(t, "nas")); err != nil {
					t.Fatal(err)
				}
				raw, err := enrollreq.Encode(&reenroll)
				if err != nil {
					t.Fatal(err)
				}
				change.T, change.TS, change.Body = "enroll", 1_760_100_003, map[string]any{"request": raw}
				entries = append(entries, sign(change, "signer1", "signer2"))
			}
			head := replay.Replay(a.replayAnchor(), entries)
			prefix := replay.Replay(a.replayAnchor(), entries[:split])
			if len(head.Rejected) != 0 {
				t.Fatalf("history rejected: %v", head.Rejected)
			}
			tree, err := tlog.Build(entries)
			if err != nil {
				t.Fatal(err)
			}
			conflictAfter := uint64(split)
			conflict := &entry.Envelope{V: entry.Version, T: "note", Net: doc.Net,
				TS: 1_760_100_001, After: &conflictAfter, Body: map[string]any{"text": "the other branch"}}
			branch := append(append([][]byte(nil), entries[:split]...), sign(conflict, "signer1"))
			other, err := tlog.Build(branch)
			if err != nil {
				t.Fatal(err)
			}
			signed := func(tree *tlog.Tree) string {
				t.Helper()
				text, err := tree.Checkpoint(doc.Origin).Sign(fixtureKey(t, "logkey"))
				if err != nil {
					t.Fatal(err)
				}
				text, err = cosign.Append(fixtureWitnesses(t), cosign.At(time.Unix(fixtureCosignedAt, 0)))(text)
				if err != nil {
					t.Fatal(err)
				}
				return text
			}
			ev, err := forkevidence.Build(tree, other, signed(tree), signed(other))
			if err != nil {
				t.Fatal(err)
			}
			ev.Policy = doc.Policy
			finding, err := forkevidence.Check(ev, doc.Origin, []string{doc.LogKey}, doc.Policy)
			if err != nil || finding.Split != split || finding.Size != split+1 {
				t.Fatalf("history must prove a fork at split %d: %v (%v)", split, finding, err)
			}
			held := *served
			held.State, held.Served, held.Tree = head, entries, tree
			held.Checkpoint = tree.Checkpoint(doc.Origin)
			oldKey, err := keyOf(prefix.Devices["nas"].WgPk)
			if err != nil {
				t.Fatal(err)
			}
			secondKey, err := keyOf(hex.EncodeToString(otherKey))
			if err != nil {
				t.Fatal(err)
			}
			atPrefix, atHead := provenKeysIn(t, prefix, &held), provenKeysIn(t, head, &held)
			if atPrefix[oldKey] != "nas" || atHead[oldKey] != "nas" ||
				prefix.Devices["nas"].Version != 1 || head.Devices["nas"].Version != uint64(split+1) {
				t.Fatal("nas must be proven at both ends with key K and a changed version")
			}
			peers, _, why := a.frozenSet(&held, finding.Split, finding.SplitRoot, peertable.Key{})
			if why != "" {
				t.Fatal(why)
			}
			got := map[peertable.Key]bool{}
			for _, peer := range peers {
				got[peer.Key] = true
				if peer.Key == oldKey || peer.Key == secondKey {
					t.Error("nas changed after the split but kept a key in the frozen set")
				}
			}
			for key, id := range atPrefix {
				if id != "nas" && !got[key] {
					t.Errorf("unchanged device %s was dropped", id)
				}
			}
			if len(atPrefix) != int(split-1) || len(peers) != int(split-2) {
				t.Errorf("prefix peers=%d, frozen peers=%d; want %d and %d", len(atPrefix), len(peers), split-1, split-2)
			}
		})
	}
}
