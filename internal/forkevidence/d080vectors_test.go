package forkevidence

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
)

// Both readers receive the same evidence; only a verified replay teaches the
// second reader the key. The original evidence is sound for either reader.
func TestD080ShippedRotatedEvidenceHasBothReaderAnswers(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var manifest struct {
		RotatedKey struct {
			File, Fresh, Informed string
			SignedBy              string `json:"signed_by"`
		} `json:"rotated_key"`
	}
	if err := json.Unmarshal(read(t, "fork/cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	c := manifest.RotatedKey
	if c.File != "evidence-rotated-key.cbor" || c.Fresh != "held" || c.Informed != "accept" {
		t.Error("fork/evidence-rotated-key must name fresh held and informed accept")
	}
	var rotated struct {
		SignedBy string `json:"signed_by"`
	}
	if err := json.Unmarshal(read(t, "proofs-rotated/cases.json"), &rotated); err != nil {
		t.Fatal(err)
	}
	if c.SignedBy != rotated.SignedBy {
		t.Fatal("evidence must use proofs-rotated's key")
	}
	published, err := hex.DecodeString(rotated.SignedBy)
	if err != nil {
		t.Fatal(err)
	}
	doc := shippedAnchor(t, root)
	result, err := logclient.Verify(logclient.Dir(filepath.Join(root, "served")), logclient.Anchor{
		Anchor: replay.FromTrust(doc), Origin: doc.Origin, LogKeys: []string{doc.LogKey}, Policy: doc.Policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := append([]string{doc.LogKey}, logclient.KeysFrom(doc.Origin, result.State)...)
	if len(keys) < 2 {
		t.Fatal("verified replay must learn a rotated key")
	}
	for _, reader := range []string{"fresh", "informed"} {
		t.Run(reader, func(t *testing.T) {
			trusted, policy := []string{doc.LogKey}, doc.Policy
			if reader == "informed" {
				trusted, policy = keys, logclient.PolicyFrom(result.State)
			}
			sound, err := Parse(read(t, "fork/evidence.cbor"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Check(sound, doc.Origin, trusted, policy); err != nil {
				t.Fatal(err)
			}
			ev, err := Parse(read(t, "fork/evidence-rotated-key.cbor"))
			if err != nil {
				t.Fatal(err)
			}
			for _, head := range []string{ev.Held, ev.Conflicting} {
				if _, err := tlog.Verify(head, []string{note.VerifierKey(doc.Origin, published)}); err != nil {
					t.Fatalf("both heads must verify under proofs-rotated's key: %v", err)
				}
			}
			finding, err := Check(ev, doc.Origin, trusted, policy)
			if reader == "fresh" {
				if code, _ := evrefusal.CodeOf(err); code != evrefusal.Held {
					t.Fatalf("Go answers %q (%v), SPEC states held", code, err)
				}
			} else if err != nil || finding.Size != sound.Size || finding.Split != sound.Split {
				t.Fatalf("informed reader must prove the sound twin's fork: %+v, %v", finding, err)
			}
			// Only log signatures change; tree claims and witness lines stay sound.
			for _, pair := range [][2]string{{ev.Held, sound.Held}, {ev.Conflicting, sound.Conflicting}} {
				body, lines, err := note.Split(pair[0])
				if err != nil {
					t.Fatal(err)
				}
				twinBody, twinLines, err := note.Split(pair[1])
				if err != nil || body != twinBody {
					t.Fatal("checkpoint bodies must match the sound twin")
				}
				witnesses := func(lines []note.Signature) []note.Signature {
					var out []note.Signature
					for _, line := range lines {
						if strings.HasPrefix(line.Name, "norn-witness/") {
							out = append(out, line)
						}
					}
					return out
				}
				if !reflect.DeepEqual(witnesses(lines), witnesses(twinLines)) {
					t.Fatal("witness lines must be unchanged")
				}
				for _, line := range lines {
					if line.Name == doc.Origin && bytes.Equal(line.KeyID, twinLines[0].KeyID) {
						t.Fatal("rotated evidence must have no trust-key signature")
					}
				}
			}
			ev.Held, ev.Conflicting = sound.Held, sound.Conflicting
			restored, err := ev.Encode()
			if err != nil || !bytes.Equal(restored, read(t, "fork/evidence.cbor")) {
				t.Fatal("restoring heads must recover sound evidence")
			}
			answer := "held"
			if reader == "informed" {
				answer = "accept (fork proved)"
			}
			t.Logf("fork/evidence-rotated-key.cbor %s: %s", reader, answer)
		})
	}
}
