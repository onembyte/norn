package ots

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Cold-model gate run 11, defect D11 ---------------------------------
//
// `anchors/` shipped with no `cases.json`, no mention in §12.1 in either the
// vectored or the not-vectored list, and a one-line §12 entry that repeats the
// ambiguous word "checkpoint body" *without* §6's disambiguating clause. The
// `.ots` container format is described nowhere in `SPEC.md` either, so run 11
// had to recognise the OpenTimestamps magic from outside knowledge to extract
// a digest at all.
//
// The fix is a manifest that states the digest and the bytes that produce it,
// so the rule is vectored without a reader having to parse OpenTimestamps —
// and this test recomputes it, so it cannot go stale when the log grows.

func TestTheAnchorsDeclareTheDigestTheyStamp(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "anchors", "cases.json"))
	if err != nil {
		t.Fatalf("`anchors/` ships no manifest, so nothing tells a reader which bytes "+
			"a stamp covers: %v", err)
	}
	var doc struct {
		Cases []struct {
			Name   string `json:"name"`
			Over   string `json:"over"`
			Digest string `json:"digest"`
			Says   string `json:"says"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("the manifest lists no case")
	}

	var checked int
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			proof, err := os.ReadFile(filepath.Join(root, "anchors", c.Name))
			if err != nil {
				t.Fatalf("the manifest names a file that does not ship: %v", err)
			}
			if c.Over == "" {
				// A proof over an arbitrary digest: it states the digest and
				// nothing produces it. Still has to chain.
				want, err := hex.DecodeString(c.Digest)
				if err != nil || len(want) != sha256.Size {
					t.Fatalf("`digest` is not 32 hex bytes: %q", c.Digest)
				}
				if _, err := Parse(proof); err != nil {
					t.Fatalf("the proof does not parse: %v", err)
				}
				return
			}

			// The whole point: the digest is recomputed from the named bytes,
			// so the manifest cannot drift from the file it describes.
			source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(c.Over)))
			if err != nil {
				t.Fatalf("the manifest names a source file that does not ship: %v", err)
			}
			body, _, found := strings.Cut(string(source), "\n\n")
			if !found {
				t.Fatalf("%s has no blank separator line", c.Over)
			}
			// §6: the three body lines **plus** the blank line — four 0x0A in
			// all, not the three of §7's signed text.
			stamped := body + "\n\n"
			sum := sha256.Sum256([]byte(stamped))
			if got := hex.EncodeToString(sum[:]); got != c.Digest {
				t.Errorf("the manifest says %s\nthe named bytes hash to %s\n"+
					"(if this is a stale manifest, regenerate `anchors/` — the "+
					"digest moves whenever the tree does)", c.Digest, got)
			}
			if _, err := CheckAnchor(proof, stamped); err != nil {
				t.Errorf("the shipped proof does not chain from the digest the "+
					"manifest declares: %v", err)
			}
			if c.Says == "" {
				t.Error("the case says nothing about which bytes it covers, which is " +
					"the one thing a reader needs and cannot derive")
			}
			checked++
		})
	}
	if checked == 0 {
		t.Error("no case names the bytes it is over, so the manifest states a digest " +
			"and proves nothing about where it comes from")
	}
}
