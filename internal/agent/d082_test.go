package agent

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
)

// A trust file carrying a rotated key is an operator's mistake, not a way
// to catch up. The dup-key rule includes the anchor; replay's resulting
// divergence is why every trust file must keep the network's initial values.
func TestAReissuedTrustFileWithARotatedKeyDivergesAndTheSpecExplainsWhy(t *testing.T) {
	_, held := heldServed(t)
	initial := replay.Replay(replay.FromTrust(anchor(t)), held.Served)
	reissued := replay.Replay(replay.FromTrust(rotatedAnchor(t)), held.Served)
	for _, c := range []struct {
		index uint64
		want  string
	}{{27, replay.ReasonDupKey}, {90, replay.ReasonStaleState}} {
		got := "accept"
		for _, r := range initial.Rejected {
			if r.Index == c.index {
				t.Fatalf("initial trust refused entry %d: %s", c.index, r.Reason)
			}
		}
		for _, r := range reissued.Rejected {
			if r.Index == c.index {
				got = r.Reason
			}
		}
		if got != c.want {
			t.Errorf("reissued trust entry %d = %s, want %s", c.index, got, c.want)
		}
	}
	if len(initial.LogKeys) != 2 || len(reissued.LogKeys) != 0 || reissued.Versions["log_key"] != 0 {
		t.Errorf("learned keys: initial=%v reissued=%v version=%d", initial.LogKeys, reissued.LogKeys, reissued.Versions["log_key"])
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(raw)), " ")
	if !strings.Contains(text, "**Every trust file for a network names the same initial `log_key` and `policy`** (D-082 (2)).") {
		t.Error("SPEC §9.4 must explain why reissuing with a rotated key is not conforming")
	}
	t.Log("reissued trust: entry 27 dup-key, entry 90 stale-state, no learned key")
}

// Both states prove nas by device id, but the prefix never proved its new
// key and its old key may be the reason it rotated. Neither belongs in the
// frozen set (D-082 (3)). Build the reader's P23 with the fixture signers.
func TestADeviceThatRotatedAfterTheSplitKeepsNeitherKeyInTheFrozenSet(t *testing.T) {
	a, served := heldServed(t)
	wg, err := hex.DecodeString("ae5ee1982d4db333d00110bdccb68b845775e2f0676f154766d092b82eaafb14")
	if err != nil {
		t.Fatal(err)
	}
	prev := uint64(35)
	env := &entry.Envelope{V: entry.Version, T: "rotate", Net: anchor(t).Net,
		TS: 1_760_009_000, Prev: &prev, Body: map[string]any{"device_id": "nas", "wg_pk": wg}}
	for _, name := range []string{"signer1", "signer3", "nas"} {
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
	entries := append(append([][]byte(nil), served.Served[:40]...), raw)
	prefix := replay.Replay(a.replayAnchor(), entries[:40])
	head := replay.Replay(a.replayAnchor(), entries)
	for _, r := range head.Rejected {
		if r.Index == 40 {
			t.Fatalf("rotation rejected: %v", r)
		}
	}
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	held := *served
	held.State, held.Served, held.Tree = head, entries, tree
	held.Checkpoint.Size = int64(len(entries))
	root, err := tree.HeadAt(40)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := keyOf(prefix.Devices["nas"].WgPk)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := keyOf(head.Devices["nas"].WgPk)
	if err != nil || oldKey == newKey || head.Devices["nas"].Version != 40 {
		t.Fatalf("rotation did not change the key at index 40: %v", err)
	}
	if provenKeysIn(t, prefix, &held)[oldKey] != "nas" || provenKeysIn(t, head, &held)[newKey] != "nas" {
		t.Fatal("nas must be proven at both the prefix and the held head")
	}
	peers, _, why := a.frozenSet(&held, 40, root, peertable.Key{})
	if why != "" {
		t.Fatal(why)
	}
	if len(peers) != 2 {
		t.Errorf("frozen peers=%d, want the two unchanged peers", len(peers))
	}
	for _, peer := range peers {
		if peer.Key == oldKey || peer.Key == newKey {
			t.Error("a device that rotated after the split kept a key in the frozen set")
		}
	}
}
