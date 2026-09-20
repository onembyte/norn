package main

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
)

// `ENROLLMENT.md` R2, step one: "`norn audit --by <kid> --since <t>` lists
// everything that key signed". It is what an operator runs the moment a signer
// key is stolen — not "revoke it", but **"what did they do with it"**, which
// is the question `revoke` cannot answer and the log can.

func auditArgs(t *testing.T, extra ...string) []string {
	t.Helper()
	return append([]string{"audit", "-trust", filepath.Join(vectors(), "trust.cbor"),
		"-log", filepath.Join(vectors(), "served")}, extra...)
}

// The kid of a signer the fixture uses on most of its entries.
func signerKid(t *testing.T) string {
	t.Helper()
	return kidOf(t, "signer1")
}

func TestAuditListsWhatOneKeySigned(t *testing.T) {
	bin := nornBinary(t)

	out, stderr, err := run(t, bin, auditArgs(t, "-by", signerKid(t))...)
	if err != nil {
		t.Fatalf("audit: %v\n%s", err, stderr)
	}

	if !strings.Contains(out, signerKid(t)) {
		t.Errorf("the key being audited should be named:\n%s", out)
	}
	// In plain words, like everything else an operator reads.
	if !strings.Contains(out, "enrolled") {
		t.Errorf("entries should read as sentences:\n%s", out)
	}
	// And with indexes, because the next thing an operator does is fetch a
	// proof for one of them.
	if !strings.Contains(out, "entry") {
		t.Errorf("each line should name the entry it is:\n%s", out)
	}
}

// A key that signed nothing is a real answer, not an error: it is the answer
// an operator most wants after a scare.
func TestAuditSaysWhenAKeySignedNothing(t *testing.T) {
	bin := nornBinary(t)

	out, stderr, err := run(t, bin, auditArgs(t, "-by", "00000000deadbeef")...)
	if err != nil {
		t.Fatalf("audit: %v\n%s", err, stderr)
	}
	if !strings.Contains(out, "nothing") {
		t.Errorf("a key that signed nothing should be said plainly:\n%s", out)
	}
}

// `--since` narrows the list -- and the command says what that costs, because
// `ts` is the signer's own claim and a thief sets it.
func TestAuditWarnsThatSinceFiltersAFieldTheSuspectControls(t *testing.T) {
	bin := nornBinary(t)

	out, stderr, err := run(t, bin, auditArgs(t, "-by", signerKid(t),
		"-since", "2026-01-01T00:00:00Z")...)
	if err != nil {
		t.Fatalf("audit: %v\n%s", err, stderr)
	}
	combined := out + stderr
	if !strings.Contains(combined, "whoever signed") && !strings.Contains(combined, "controls") {
		t.Errorf("filtering on a timestamp the suspect chose should carry a "+
			"warning:\n%s", combined)
	}
}

// Auditing needs a key to audit.
func TestAuditNeedsAKey(t *testing.T) {
	bin := nornBinary(t)

	if _, stderr, err := run(t, bin, auditArgs(t)...); err == nil {
		t.Fatal("audit ran with no key to audit")
	} else if !strings.Contains(stderr, "-by") {
		t.Errorf("the error should say what is missing:\n%s", stderr)
	}
}

// A malformed kid is refused rather than silently matching nothing, which
// would read exactly like "this key signed nothing" -- the most dangerous
// wrong answer this command can give.
func TestAMalformedKeyIdIsRefused(t *testing.T) {
	bin := nornBinary(t)

	if _, stderr, err := run(t, bin, auditArgs(t, "-by", "not-a-kid")...); err == nil {
		t.Fatal("a malformed key id was accepted, and would have reported that the " +
			"key signed nothing")
	} else if !strings.Contains(stderr, "key id") {
		t.Errorf("the error should say what a key id looks like:\n%s", stderr)
	}
}

// Entries the log published and replay refused are shown too, marked as such.
// A stolen key's attempts matter whether or not they worked.
func TestAuditShowsRejectedEntriesToo(t *testing.T) {
	bin := nornBinary(t)

	out, _, err := run(t, bin, auditArgs(t, "-by", signerKid(t), "-all")...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "rejected") {
		t.Errorf("-all should include what the log carried but replay refused:\n%s",
			firstN(out, 2000))
	}
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// kidOf is a fixture key's id, as the entries carry it.
func kidOf(t *testing.T, name string) string {
	t.Helper()
	key := fixtureKey(t, name)
	return entry.Kid(key.Public().(ed25519.PublicKey))
}
