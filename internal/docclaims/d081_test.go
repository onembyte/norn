package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-081 (row F6). On the IETF KEYTRANS list it was suggested that each entry
// name the policy it was authorized under. The owner answered 1-A, 2-A: v1
// keeps authority bound by position and §4.4 says why, and replay does not
// compare one device's grant with another's, which §4.3 says. The answer
// lives in four documents that must agree, and each SPEC sentence must sit in
// its own section.
func TestAnEntryNamesNoAuthorityVersionAndTheSpecSaysWhy(t *testing.T) {
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(raw)), " ")
	}
	between := func(doc, name, from, to string) string {
		start := strings.Index(doc, from)
		if start < 0 {
			t.Fatalf("%s has no %q", name, from)
		}
		end := strings.Index(doc[start:], to)
		if end < 0 {
			t.Fatalf("%s has no %q after %q", name, to, from)
		}
		return doc[start : start+end]
	}
	spec := read("SPEC.md")
	guards := between(spec, "SPEC.md", "### 4.4 ", "### 4.5 ")
	for _, want := range []string{
		"No entry names the authority it was signed under (D-081).",
		"v1 has no field naming a signer-set, root-set, `params`, policy or log-key version that must still be current when the entry lands.",
		"every entry it would add to the refusals is one whose signers still qualify where it takes effect",
		"an entry whose signers no longer qualify, because a signer was removed or a threshold raised, fails §4.3 at landing (`threshold`), and a change to the entry's own object fails `prev` (`stale-state`)",
	} {
		if !strings.Contains(guards, want) {
			t.Errorf("SPEC.md §4.4 does not say %q", want)
		}
	}
	types := between(spec, "SPEC.md", "### 4.3 ", "### 4.4 ")
	for _, want := range []string{
		"Grants are not compared across devices (D-081).",
		"an `enroll` whose grant (§4.0) overlaps an active device's grant is accepted",
		"What a node installs for two peers whose allowed-ips overlap is not a replay rule",
	} {
		if !strings.Contains(types, want) {
			t.Errorf("SPEC.md §4.3 does not say %q", want)
		}
	}

	decisions := read("DECISIONS.md")
	start := strings.Index(decisions, "## D-081")
	if start < 0 {
		t.Fatal("DECISIONS.md has no D-081")
	}
	d081 := decisions[start:]
	for _, want := range []string{
		"**1-A, 2-A**",
		"No field names a signer-set, root-set, `params`, policy or log-key version",
		"Text only: nothing a conforming implementation accepts or refuses changes",
		"replay does not compare one device's grant with another's",
	} {
		if !strings.Contains(d081, want) {
			t.Errorf("DECISIONS.md D-081 does not say %q", want)
		}
	}
	if !strings.Contains(read("HARDENING-PLAN.md"), "D-081 (taken 2026-10-23") {
		t.Error("HARDENING-PLAN.md §2 does not list D-081 with its date")
	}

	// The row that records the answer is not the block; the block itself must
	// carry it, and the question must no longer read as open.
	ledger := read("BUILD-LOG.md")
	if strings.Contains(ledger, "## DECISION NEEDED — F6") {
		t.Error("BUILD-LOG.md still has F6 as DECISION NEEDED")
	}
	start = strings.Index(ledger, "## DECISION TAKEN — F6")
	if start < 0 {
		t.Fatal("BUILD-LOG.md has no DECISION TAKEN — F6")
	}
	block := ledger[start:]
	if end := strings.Index(block[1:], "## DECISION TAKEN"); end > 0 {
		block = block[:end+1]
	}
	if !strings.Contains(block, "(global rule 14a): 1-A, 2-A") {
		t.Error("the F6 block does not record the owner's two answers")
	}
}
