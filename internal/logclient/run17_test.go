package logclient

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

func TestRunSeventeenAnAnchoredGenesisMustActuallyApply(t *testing.T) {
	root := vectorRoot()
	dir := filepath.Join(root, "genesis-unapplied")
	raw := []byte(readFile(t, filepath.Join(dir, "trust.cbor")))
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Cases []struct{ Name, Serve string }
		Codes map[string]string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Cases) != 2 {
		t.Fatal("manifest must include rejected and sound logs")
	}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			anchor := shippedLogAnchor(t)
			want := "accept"
			if c.Name == "unapplied" {
				anchor.Anchor = replay.FromTrust(doc)
				want = "genesis"
			} else if c.Name != "sound" {
				t.Fatal("unexpected case")
			}
			if manifest.Codes[c.Name] != want {
				t.Fatal("wrong manifest code")
			}
			runFourteenAnswer(t, filepath.Join(dir, c.Serve), anchor, want)
		})
	}
	bad := []byte(readFile(t, filepath.Join(dir, "entry.cbor")))
	if !bytes.Equal(entry.LeafHash(bad), doc.GenesisHash) {
		t.Fatal("anchor must pin exactly the malformed genesis")
	}
	env, err := entry.Decode(bad)
	if err != nil {
		t.Fatal(err)
	}
	sound, err := entry.Decode([]byte(readFile(t, filepath.Join(root, "log", "0-genesis.cbor"))))
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Sigs) != 1 || len(sound.Sigs) != 2 {
		t.Fatal("remove exactly one of two root signatures")
	}
	env.Sigs = sound.Sigs
	fixed, err := entry.Encode(env)
	if err != nil || !bytes.Equal(fixed, []byte(readFile(t, filepath.Join(root, "log", "0-genesis.cbor")))) {
		t.Fatal("restoring signatures must recover genesis")
	}
	st := replay.Replay(replay.FromTrust(doc), [][]byte{bad})
	if len(st.Devices) != 0 || len(st.Rejected) != 1 || st.Rejected[0].Reason != "bad-genesis" {
		t.Fatalf("expected genesis abort and empty set: %+v", st)
	}
	// No unrelated trust member may change.
	base, err := trust.Parse([]byte(readFile(t, filepath.Join(root, "trust.cbor"))))
	if err != nil {
		t.Fatal(err)
	}
	base.GenesisHash = doc.GenesisHash
	encoded, err := base.Encode()
	if err != nil || !bytes.Equal(encoded, raw) {
		t.Fatal("only genesis_hash may differ")
	}
}

func TestRunSeventeenQuorumNoneAcceptsBothHeads(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "quorum-none")
	doc, err := trust.Parse([]byte(readFile(t, filepath.Join(dir, "trust.cbor"))))
	if err != nil {
		t.Fatal(err)
	}
	base, err := trust.Parse([]byte(readFile(t, filepath.Join(vectorRoot(), "trust.cbor"))))
	if err != nil {
		t.Fatal(err)
	}
	base.Policy = doc.Policy
	raw, err := base.Encode()
	if err != nil || !bytes.Equal(raw, []byte(readFile(t, filepath.Join(dir, "trust.cbor")))) {
		t.Fatal("only trust policy may differ")
	}
	anchor := shippedLogAnchor(t)
	anchor.Policy = doc.Policy
	for _, file := range []string{"uncosigned.checkpoint", "../served/checkpoint"} {
		t.Run(file, func(t *testing.T) {
			head := readFile(t, filepath.Join(dir, file))
			result := runFourteenAnswer(t, servedWith(t, filepath.Join(vectorRoot(), "served"), head), anchor, "accept")
			if result.QuorumTime != nil {
				t.Fatal("quorum none supplies no corroborated time, even with cosignatures")
			}
		})
	}
	// A real quorum still has a clock and accepts the same sound head.
	if result := runFourteenAnswer(t, filepath.Join(vectorRoot(), "served"), shippedLogAnchor(t), "accept"); result.QuorumTime == nil {
		t.Fatal("sound twin must have quorum time")
	}
	if _, err := os.Stat(filepath.Join(dir, "cases.json")); err != nil {
		t.Fatal(err)
	}
}
