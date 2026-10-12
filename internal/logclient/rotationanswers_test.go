package logclient

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/refusal"
)

// Cold gate run 13, D16. §12.1 says `served-rotated/` pins that the anchor key
// is kept alongside the keys a node learns, and `served-superseded/` that a
// raised quorum binds the nodes already watching -- but neither manifest asked.
// `served-rotated/` stated only "refuse fresh, accept informed", so a reader
// that replaced the trust key with the learned one passed while refusing the
// head its log is actually serving; and `served-superseded/`'s informed refusal
// had no code, so the same reader refused it for `log-signature` instead of
// `quorum` and passed again. The answers live in the manifests now, and this
// reads each back against the verifier: fresh is `trust.cbor` alone, informed
// is the reader that replayed `served/`.
func TestTheRotationManifestsStateEveryAnswer(t *testing.T) {
	checkRunFourteenLearnedKeys(t)
	fresh := shippedLogAnchor(t)
	honest := filepath.Join(vectorRoot(), "served")
	held, err := Verify(Dir(honest), fresh)
	if err != nil {
		t.Fatal(err)
	}
	informed := fresh
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
	}

	for _, c := range []struct {
		dir                          string
		fresh, informed, readsServed string
	}{
		// The rotated head, and the head the log is serving under the anchor
		// key: an informed reader keeps that key alongside and accepts both.
		{"served-rotated", "log-signature", "accept", "accept"},
		// Two of three cosigned: enough for the trust file, not for the
		// replayed policy that raised the quorum to three.
		{"served-superseded", "accept", "quorum", ""},
	} {
		t.Run(c.dir, func(t *testing.T) {
			answers.Fresh, answers.Informed, answers.InformedReadsServed = "", "", ""
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
			if c.readsServed != "" {
				if got := answer(honest, informed); got != c.readsServed {
					t.Errorf("an informed reader answers %q on served/checkpoint; cases.json "+
						"says %q -- the anchor key is kept alongside (§9.4)", got, c.readsServed)
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
