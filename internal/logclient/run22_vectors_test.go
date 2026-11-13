package logclient

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/trust"
)

// A held tree keeps the evidence of its acceptance, even when its next copy
// could not meet that accepting policy's quorum on its own.
func TestAThinCopyOfAHeldHeadDoesNotFaceQuorumAgain(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "served-superseded")
	var meta struct {
		Thin struct {
			File, Fresh, Informed, Retains string
			Time                           int64 `json:"informed_quorum_time"`
		} `json:"thin_copy"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &meta); err != nil {
		t.Fatal(err)
	}
	c := meta.Thin
	if c.File != "one-cosignature.checkpoint" || c.Fresh != "quorum" || c.Informed != "accept" || c.Retains != "../served/checkpoint" || c.Time != 1760003607 {
		t.Fatal("missing thin-copy readers and retained acceptance")
	}
	served := filepath.Join(vectorRoot(), "served")
	honest := readFile(t, filepath.Join(dir, c.Retains))
	thin := readFile(t, filepath.Join(dir, c.File))
	var kept strings.Builder
	for _, line := range strings.SplitAfter(honest, "\n") {
		if strings.HasPrefix(line, note.SigPrefix+"norn-witness/vps ") || strings.HasPrefix(line, note.SigPrefix+"norn-witness/friend ") {
			continue
		}
		kept.WriteString(line)
	}
	if thin != kept.String() {
		t.Fatal("thin copy must delete only vps and friend")
	}
	fresh := shippedLogAnchor(t)
	held, err := Verify(Dir(served), fresh)
	if err != nil {
		t.Fatal(err)
	}
	before := *held
	before.Cosignatures = append([]cosign.Cosignature(nil), held.Cosignatures...)
	if held.QuorumTime == nil || held.QuorumTime.Unix() != c.Time || len(held.Cosignatures) != 3 || held.AcceptancePolicy != fresh.Policy {
		t.Fatal("initial acceptance is not the full trust-policy acceptance")
	}
	at := *held.QuorumTime
	before.QuorumTime = &at
	for _, mode := range []string{"fresh", "Verify", "VerifyFrom"} {
		t.Run(mode, func(t *testing.T) {
			a := fresh
			if mode != "fresh" {
				a.Policy = PolicyFrom(held.State)
				a.Stored, a.Held, a.StoredResult = &held.Checkpoint, held.Tree, held
			}
			f := Dir(servedWith(t, served, thin))
			var got *Result
			var e error
			if mode == "VerifyFrom" {
				got, e = VerifyFrom(held, f, a)
			} else {
				got, e = Verify(f, a)
			}
			if mode == "fresh" {
				if code, _ := refusal.CodeOf(e); string(code) != c.Fresh {
					t.Fatalf("fresh thin copy = %q (%v), want quorum", code, e)
				}
				return
			}
			if e != nil {
				t.Fatalf("held thin copy: %v", e)
			}
			for _, result := range []*Result{held, got} {
				if result.SignedCheckpoint != before.SignedCheckpoint || result.AcceptancePolicy != before.AcceptancePolicy || !reflect.DeepEqual(result.Cosignatures, before.Cosignatures) || !reflect.DeepEqual(result.QuorumTime, before.QuorumTime) {
					t.Fatal("thin copy changed stored note, cosignatures, accepting policy or T")
				}
			}
		})
	}
}

// Recording the fetches distinguishes a missing full hash tile from the
// earlier checkpoint and entry-bundle acquisition steps sharing its code.
func TestAMissingFullTileIsUnservedAtTheHashTileStep(t *testing.T) {
	cases, codes, serveOver := servedNegatives(t)
	for _, c := range cases {
		if c.Name != "missing-full-hash-tile" {
			continue
		}
		if c.Path != "tile/0/000" || !c.Remove || codes[c.Name] != refusal.Unserved || filepath.Base(serveOver) != "served-large" {
			t.Fatal("missing full-tile deletion contract")
		}
		dir := c.apply(t, serveOver)
		f := &runTwentyTwoFetches{Fetcher: Dir(dir)}
		_, err := Verify(f, shippedLogAnchor(t))
		if code, _ := refusal.CodeOf(err); code != refusal.Unserved || !strings.Contains(err.Error(), c.Path) {
			t.Fatalf("missing full tile = %q (%v), want unserved at step 12", code, err)
		}
		want := []string{"checkpoint", "tile/entries/000", "tile/entries/001.p/44", "tile/0/000"}
		if !reflect.DeepEqual(f.paths, want) {
			t.Fatalf("fetches = %v, want %v", f.paths, want)
		}
		write(t, filepath.Join(dir, c.Path), readFile(t, filepath.Join(vectorRoot(), serveOver, c.Path)))
		if _, err := Verify(Dir(dir), shippedLogAnchor(t)); err != nil {
			t.Fatalf("full-tile-only repair: %v", err)
		}
		return
	}
	t.Fatal("missing missing-full-hash-tile case")
}

type runTwentyTwoFetches struct {
	Fetcher
	paths []string
}

func (f *runTwentyTwoFetches) Fetch(path string) ([]byte, error) {
	f.paths = append(f.paths, path)
	return f.Fetcher.Fetch(path)
}

func TestQuorumNoneStillChecksEachListedWitnessLine(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "quorum-none")
	var meta struct {
		Trust string
		Cases []struct{ Name, File, Says string }
		Codes map[string]string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &meta); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range meta.Cases {
		if c.Name == "forged-pi" {
			found = c.File == "forged-pi.checkpoint" && c.Says != ""
		}
	}
	if !found || meta.Codes["forged-pi"] != "cosignature" {
		t.Fatal("missing forged listed line under quorum none")
	}
	doc, err := trust.Parse([]byte(readFile(t, filepath.Join(dir, meta.Trust))))
	if err != nil {
		t.Fatal(err)
	}
	a := shippedLogAnchor(t)
	a.Policy = doc.Policy
	served := filepath.Join(vectorRoot(), "served")
	honest := readFile(t, filepath.Join(served, "checkpoint"))
	forged := readFile(t, filepath.Join(dir, "forged-pi.checkpoint"))
	if forged != forgeWitnessLine(t, honest, "pi") {
		t.Fatal("only pi's last signature byte may change")
	}
	if _, e := Verify(Dir(servedWith(t, served, forged)), a); e == nil {
		t.Fatal("forged listed line accepted under quorum none")
	} else if code, _ := refusal.CodeOf(e); code != refusal.Cosignature {
		t.Fatal(e)
	}
	repaired, err := Verify(Dir(servedWith(t, served, forgeWitnessLine(t, forged, "pi"))), a)
	if err != nil || repaired.QuorumTime != nil {
		t.Fatal("byte-only repair must accept with no T", err)
	}
}

func TestCaseVariantsOfListedSignatureNamesAreStrangers(t *testing.T) {
	served := filepath.Join(vectorRoot(), "served")
	fresh := shippedLogAnchor(t)
	held, err := Verify(Dir(served), fresh)
	if err != nil {
		t.Fatal(err)
	}
	honest := readFile(t, filepath.Join(served, "checkpoint"))
	for _, kind := range []string{"witness", "log"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(vectorRoot(), "served-upper-"+kind+"-name")
			var meta struct {
				ServeOver       string `json:"serve_over"`
				Fresh, Informed string
			}
			if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &meta); err != nil {
				t.Fatal(err)
			}
			if meta.ServeOver != "served" || meta.Fresh != "accept" || meta.Informed != "accept" {
				t.Fatal("both readers must accept")
			}
			head := readFile(t, filepath.Join(dir, "checkpoint"))
			_, sigs, err := note.Split(honest)
			if err != nil {
				t.Fatal(err)
			}
			name := fresh.Origin
			payload := make([]byte, 68)
			if kind == "witness" {
				name = "norn-witness/pi"
				payload = make([]byte, 76)
				binary.BigEndian.PutUint64(payload[4:12], 1760003700)
			}
			for _, sig := range sigs {
				if sig.Name == name {
					copy(payload, sig.KeyID)
				}
			}
			line := note.SigPrefix + strings.ToUpper(name) + " " + base64.StdEncoding.EncodeToString(payload) + "\n"
			if head != honest+line || strings.TrimSuffix(head, line) != honest {
				t.Fatal("removing only the case-variant stranger must recover served exactly")
			}
			for _, reader := range []string{"fresh", "informed"} {
				t.Run(reader, func(t *testing.T) {
					a := fresh
					if reader == "informed" {
						a.Policy = PolicyFrom(held.State)
						a.Stored, a.Held, a.StoredResult = &held.Checkpoint, held.Tree, held
					}
					if _, err := Verify(Dir(servedWith(t, served, head)), a); err != nil {
						t.Fatalf("case-variant stranger: %v", err)
					}
					if _, err := Verify(Dir(servedWith(t, served, strings.TrimSuffix(head, line))), a); err != nil {
						t.Fatalf("line-only repair: %v", err)
					}
				})
			}
		})
	}
}
