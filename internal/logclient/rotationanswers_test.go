package logclient

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/refusal"
)

// The manifests pin both readers: fresh has trust.cbor alone; informed has
// verified and replayed served/ and holds its head. D-082 (1) keeps that
// head's acceptance even when served-superseded omits a witness line. The
// rotated-key case still pins that learned log keys join the trust key.
func TestTheRotationManifestsStateEveryAnswer(t *testing.T) {
	checkRunFourteenLearnedKeys(t)
	fresh := shippedLogAnchor(t)
	honest := filepath.Join(vectorRoot(), "served")
	held, err := Verify(Dir(honest), fresh)
	if err != nil {
		t.Fatal(err)
	}
	informed := fresh
	informed.Stored, informed.Held, informed.StoredResult = &held.Checkpoint, held.Tree, held
	informed.LogKeys = append(append([]string(nil), fresh.LogKeys...), KeysFrom(fresh.Origin, held.State)...)
	if published := PolicyFrom(held.State); published != "" {
		informed.Policy = published
	}
	answer := func(dir string, anchor Anchor) string {
		if _, err := Verify(Dir(dir), anchor); err != nil {
			code, _ := refusal.CodeOf(err)
			return string(code)
		}
		return "accept"
	}
	var answers struct {
		Fresh               string `json:"fresh"`
		Informed            string `json:"informed"`
		InformedReadsServed string `json:"informed_reads_served"`
		InformedQuorumTime  int64  `json:"informed_quorum_time"`
	}

	for _, c := range []struct {
		dir                          string
		fresh, informed, readsServed string
	}{
		// The rotated head, and the head the log is serving under the anchor
		// key: an informed reader keeps that key alongside and accepts both.
		{"served-rotated", "log-signature", "accept", "accept"},
		// This tree is already held: neither its acceptance nor its T changes.
		{"served-superseded", "accept", "accept", ""},
	} {
		t.Run(c.dir, func(t *testing.T) {
			answers.Fresh, answers.Informed, answers.InformedReadsServed = "", "", ""
			answers.InformedQuorumTime = 0
			raw := readFile(t, filepath.Join(vectorRoot(), c.dir, "cases.json"))
			if err := json.Unmarshal([]byte(raw), &answers); err != nil {
				t.Fatal(err)
			}
			if answers.Fresh != c.fresh || answers.Informed != c.informed ||
				answers.InformedReadsServed != c.readsServed {
				t.Fatalf("cases.json states fresh=%q informed=%q informed_reads_served=%q; "+
					"want %q, %q, %q", answers.Fresh, answers.Informed,
					answers.InformedReadsServed, c.fresh, c.informed, c.readsServed)
			}
			head := servedWith(t, honest, readFile(t, filepath.Join(vectorRoot(), c.dir, "checkpoint")))
			if got := answer(head, fresh); got != c.fresh {
				t.Errorf("a fresh reader answers %q; cases.json says %q", got, c.fresh)
			}
			if got := answer(head, informed); got != c.informed {
				t.Errorf("an informed reader answers %q; cases.json says %q", got, c.informed)
			}
			if c.dir == "served-superseded" {
				result, err := Verify(Dir(head), informed)
				if err != nil {
					t.Fatal(err)
				}
				if answers.InformedQuorumTime != 1760003607 || result.QuorumTime == nil ||
					result.QuorumTime.Unix() != answers.InformedQuorumTime {
					t.Errorf("informed reader must keep served's T=1760003607: manifest=%d result=%v",
						answers.InformedQuorumTime, result.QuorumTime)
				}
				if result.SignedCheckpoint != held.SignedCheckpoint || !reflect.DeepEqual(result.Cosignatures, held.Cosignatures) {
					t.Error("thin copy replaced the held note or cosignatures")
				}
			}
			if c.readsServed != "" {
				if got := answer(honest, informed); got != c.readsServed {
					t.Errorf("an informed reader answers %q on served/checkpoint; cases.json "+
						"says %q -- the anchor key is kept alongside (§9.4)", got, c.readsServed)
				}
			}
		})
	}
}

// The forged copy is a refusal for either history; refusing it must leave
// the held evidence available for the next read (D-084 (1)).
func TestTheSupersededManifestChecksTheForgedCopyAndRetainsTheHeldEvidence(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "served-superseded")
	var meta struct {
		ForgedCopy struct{ File, Fresh, Informed, Retains string } `json:"forged_copy"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &meta); err != nil {
		t.Fatal(err)
	}
	c := meta.ForgedCopy
	if c.File == "" || c.Fresh == "" || c.Informed == "" || c.Retains == "" {
		t.Fatal("cases.json is missing forged_copy")
	}
	raw := readFile(t, filepath.Join(dir, c.File))
	retained := readFile(t, filepath.Join(dir, c.Retains))
	if raw != forgeWitnessLine(t, retained, "pi") {
		t.Fatal("forged_copy changes more than pi's last signature byte")
	}
	honest := filepath.Join(vectorRoot(), "served")
	fresh := shippedLogAnchor(t)
	held, err := Verify(Dir(honest), fresh)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(Dir(servedWith(t, honest, raw)), fresh)
	if code, _ := refusal.CodeOf(err); string(code) != c.Fresh {
		t.Errorf("fresh forged copy = %q, want %q", code, c.Fresh)
	}
	originalCosignatures := append([]cosign.Cosignature(nil), held.Cosignatures...)
	informed := fresh
	informed.Stored, informed.Held, informed.StoredResult = &held.Checkpoint, held.Tree, held
	informed.Policy = PolicyFrom(held.State)
	for _, incremental := range []bool{false, true} {
		t.Run(map[bool]string{false: "Verify", true: "VerifyFrom"}[incremental], func(t *testing.T) {
			read := func(signed string) (*Result, error) {
				f := Dir(servedWith(t, honest, signed))
				if incremental {
					return VerifyFrom(held, f, informed)
				}
				return Verify(f, informed)
			}
			_, err := read(raw)
			if code, _ := refusal.CodeOf(err); string(code) != c.Informed {
				t.Errorf("held forged copy = %q, want %q", code, c.Informed)
			}
			// A thin honest copy still succeeds without replacing the evidence.
			result, err := read(readFile(t, filepath.Join(dir, "checkpoint")))
			if err != nil {
				t.Fatal(err)
			}
			for _, got := range []*Result{held, result} {
				if got.SignedCheckpoint != retained || !reflect.DeepEqual(got.Cosignatures, originalCosignatures) || got.QuorumTime == nil || got.QuorumTime.Unix() != 1760003607 {
					t.Error("re-read changed the retained note, cosignatures or T")
				}
			}
		})
	}
}

// Integrating 6.5l-xi-c-iii: two new rotation manifests wrote `signed_by` as a
// signed-note verifier key and left out `overlap`, where `served-rotated/`, the
// bundles and the receipts write the published key's bytes in hex beside the
// `since_index` and `overlap` of its `log_key` entry. One field with two
// encodings is a trap for a reader built from the suite alone, so each
// manifest that names a signer must name one key the replayed log published,
// in that one form.
func TestEveryRotationManifestNamesAPublishedKeyInOneForm(t *testing.T) {
	held, err := Verify(Dir(filepath.Join(vectorRoot(), "served")), shippedLogAnchor(t))
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(vectorRoot(), "served-*", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	named := 0
	for _, path := range paths {
		var manifest map[string]any
		if err := json.Unmarshal([]byte(readFile(t, path)), &manifest); err != nil {
			t.Fatal(err)
		}
		if _, ok := manifest["signed_by"]; !ok {
			continue
		}
		named++
		dir := filepath.Base(filepath.Dir(path))
		var meta struct {
			SignedBy   string  `json:"signed_by"`
			SinceIndex *uint64 `json:"since_index"`
			Overlap    *uint64 `json:"overlap"`
		}
		if err := json.Unmarshal([]byte(readFile(t, path)), &meta); err != nil {
			t.Fatal(err)
		}
		if meta.SinceIndex == nil || meta.Overlap == nil {
			t.Errorf("%s names a signer without its since_index and overlap", dir)
			continue
		}
		found := false
		for _, k := range held.State.LogKeys {
			if k.Pk == meta.SignedBy && k.SinceIndex == *meta.SinceIndex && k.Overlap == *meta.Overlap {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: signed_by %q (since %d) is not a published log key in hex", dir, meta.SignedBy, *meta.SinceIndex)
		}
	}
	if named < 3 {
		t.Fatalf("%d manifests name a signer; served-rotated and run 14's two do", named)
	}
}
