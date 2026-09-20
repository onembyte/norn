package ots

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The vector is 146 bytes written by `python-opentimestamps` -- the reference
// implementation, not this one. That is the whole reason it is here: a parser
// checked only against its own writer agrees with itself and with nobody, and
// 4.1a is this project's reminder of what that costs.
//
// Its shape is the realistic one: two branches from the same digest, one
// confirmed in a Bitcoin block and one still pending at a calendar.

func sample(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "anchors", "sample.ots"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The digest the vector was built over.
func sampleDigest(t *testing.T) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte("norn checkpoint at size 90"))
	return sum[:]
}

func TestAReferenceProofParses(t *testing.T) {
	proof, err := Parse(sample(t))
	if err != nil {
		t.Fatalf("a proof the reference implementation wrote does not parse: %v", err)
	}

	if got := hex.EncodeToString(proof.Digest); got != hex.EncodeToString(sampleDigest(t)) {
		t.Errorf("digest = %s", got)
	}
	if proof.DigestOp != "sha256" {
		t.Errorf("file hash op = %q, want sha256", proof.DigestOp)
	}

	// Both branches are there, and each says what it is.
	attestations := proof.Attestations()
	if len(attestations) != 2 {
		t.Fatalf("attestations = %+v, want two", attestations)
	}
	var bitcoin, pending int
	for _, a := range attestations {
		switch {
		case a.Bitcoin():
			bitcoin++
			if a.Height != 800000 {
				t.Errorf("block height = %d, want 800000", a.Height)
			}
		case a.Pending():
			pending++
			if !strings.Contains(a.Calendar, "opentimestamps.org") {
				t.Errorf("calendar = %q", a.Calendar)
			}
		}
	}
	if bitcoin != 1 || pending != 1 {
		t.Errorf("%d bitcoin and %d pending attestations, want one of each", bitcoin, pending)
	}
}

// What a node can actually check without asking anybody: that the operations
// really do chain from *this* digest to the value each attestation commits to.
// A tampered checkpoint fails here, offline, which is the half of T8 that does
// not need a Bitcoin node.
func TestTheOpsChainFromTheDigest(t *testing.T) {
	proof, err := Parse(sample(t))
	if err != nil {
		t.Fatal(err)
	}

	results, err := proof.Walk(sampleDigest(t))
	if err != nil {
		t.Fatalf("the proof does not chain from its own digest: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("walked to %d attestations, want two", len(results))
	}
	for _, r := range results {
		if len(r.Commitment) == 0 {
			t.Error("an attestation commits to nothing")
		}
	}
}

// The property this is for. A log that changes a checkpoint after stamping it
// has a proof that no longer chains, and that is visible with no network, no
// Bitcoin node and no trust in anybody.
func TestATamperedDigestBreaksTheChain(t *testing.T) {
	proof, err := Parse(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), sampleDigest(t)...)
	tampered[0] ^= 0x01

	if _, err := proof.Walk(tampered); err == nil {
		t.Fatal("a proof was accepted for a digest it was not made over")
	}
}

// Malformed files are refused rather than panicking: a `.ots` arrives from a
// calendar over the network, so it is somebody else's bytes.
func TestMalformedProofsAreRefused(t *testing.T) {
	good := sample(t)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"wrong magic", append([]byte("not opentimestamps at all"), good[25:]...)},
		{"truncated header", good[:20]},
		{"truncated mid-proof", good[:len(good)-5]},
		{"trailing bytes glued on", append(append([]byte(nil), good...), 0x00, 0x01)},
		{"a declared length that runs off the end", func() []byte {
			// magic, version, sha256 file op, a digest, then an attestation
			// whose payload claims to be enormous and is not there.
			bad := append([]byte(nil), magic...)
			bad = append(bad, 1, 0x08)
			bad = append(bad, make([]byte, 32)...)
			bad = append(bad, 0x00)                                           // an attestation
			bad = append(bad, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e) // pending
			return append(bad, 0xff, 0xff, 0x01)                              // ~32k, absent
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.raw); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// A version this build does not understand is refused by name, because the
// alternative is guessing at bytes that mean something else.
func TestAnUnknownVersionIsRefused(t *testing.T) {
	raw := append([]byte(nil), sample(t)...)
	raw[len(magic)] = 9

	_, err := Parse(raw)
	if err == nil {
		t.Fatal("a future version was parsed as if it were this one")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("the error should name the version: %v", err)
	}
}
