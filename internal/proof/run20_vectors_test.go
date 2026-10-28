package proof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/ed25519v1"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
	upstream "golang.org/x/mod/sumdb/tlog"
)

// The request's field rule belongs to binding even when the log included the
// refused entry. A sound head and path keep earlier steps from masking it.
func checkRequestExpiryBinding(t *testing.T) {
	t.Helper()
	const name = "request-expires-at-ts"
	var manifest struct {
		Cases []struct{ Name string }
		Codes map[string]string
		Rules map[string]struct{ Section, Says string }
	}
	if err := json.Unmarshal(d080Read(t, "proofs-bad/cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	listed := 0
	for _, c := range manifest.Cases {
		if c.Name == name {
			listed++
		}
	}
	if listed != 1 || manifest.Codes[name] != "binding" || manifest.Rules[name].Section != "8.1" || manifest.Rules[name].Says != "Decoding here is the request's structure and field rules" {
		t.Fatal("missing request-expires-at-ts binding case and request-field rule")
	}
	b, err := Decode(d080Read(t, "proofs-bad/"+name+".bundle"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Index != 132 || b.Device != "halfsigned" || !bytes.Equal(b.Entry, d080Read(t, "log/132-bad-enroll-request-expires-at-ts.cbor")) || b.Checkpoint != string(d080Read(t, "served/checkpoint")) {
		t.Fatal("must prove unchanged served entry 132 under its own id")
	}
	anchor := shippedAnchor(t)
	cp, err := tlog.Verify(b.Checkpoint, anchor.LogKeys)
	if err != nil {
		t.Fatal(err)
	}
	if err := upstream.CheckRecord(b.Proof, cp.Size, cp.Root, b.Index, tlog.LeafHash(b.Entry)); err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(b.Entry)
	if err != nil {
		t.Fatal(err)
	}
	value, err := cbor.Decode(env.Body["request"].([]byte))
	if err != nil {
		t.Fatal(err)
	}
	rawRequest := value.(map[string]any)
	if rawRequest["expires"] != rawRequest["ts"] || rawRequest["device_id"] != b.Device {
		t.Fatal("request must have expires equal to ts under its own id")
	}
	// The hostile request is signed over exactly these bytes, although the
	// strict request API rightly refuses to sign this invalid field value.
	sig := rawRequest["sig"].([]byte)
	delete(rawRequest, "sig")
	preimage, err := cbor.Encode(rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519v1.Verify(rawRequest["device_pk"].([]byte), append([]byte(enrollreq.PreimagePrefix), preimage...), sig) {
		t.Fatal("request signature must be genuine")
	}
	fixtureKey := func(name string) ed25519.PrivateKey {
		seed := sha256.Sum256([]byte("norn/testvector/v1\n" + name))
		return ed25519.NewKeyFromSeed(seed[:])
	}
	oldSignatures := append([]entry.Signature(nil), env.Sigs...)
	for _, s := range oldSignatures {
		matched := false
		for _, name := range []string{"signer1", "signer2", "signer3"} {
			public := fixtureKey(name).Public().(ed25519.PublicKey)
			if s.Kid != entry.Kid(public) {
				continue
			}
			valid, err := entry.Verify(env, s, public)
			if err != nil || !valid {
				t.Fatalf("entry signature: %v", err)
			}
			matched = true
		}
		if !matched {
			t.Fatal("entry must carry the fixture signer quorum")
		}
	}
	if len(oldSignatures) != 2 {
		t.Fatal("entry must retain both signer signatures")
	}
	rawRequest["expires"] = rawRequest["ts"].(uint64) + 1
	rawRequest["sig"] = sig
	repairedRaw, err := cbor.Encode(rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	req, err := enrollreq.Decode(repairedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := enrollreq.Sign(req, fixtureKey("halfsigned")); err != nil {
		t.Fatal(err)
	}
	if err := enrollreq.Check(req, env.Net); err != nil {
		t.Fatal(err)
	}
	env.Body["request"], err = enrollreq.Encode(req)
	if err != nil {
		t.Fatal(err)
	}
	env.Sigs = nil
	for _, s := range oldSignatures {
		for _, name := range []string{"signer1", "signer2", "signer3"} {
			key := fixtureKey(name)
			if entry.Kid(key.Public().(ed25519.PublicKey)) == s.Kid {
				if err := entry.Sign(env, key, s.Role); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	repairedEntry, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	// Changing the request changes the leaf. Rebuild its tree, signed head
	// and audit path, rather than putting new bytes under the old proof.
	tree, err := tlog.Build([][]byte{d080Read(t, "log/0-genesis.cbor"), repairedEntry})
	if err != nil {
		t.Fatal(err)
	}
	head, err := tree.Checkpoint(anchor.Origin).Sign(fixtureKey("logkey"))
	if err != nil {
		t.Fatal(err)
	}
	text, _, err := note.Split(head)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pi", "vps", "friend"} {
		line, err := cosign.Sign(text, "norn-witness/"+name, fixtureKey("witness-"+name), time.Unix(1_760_003_600, 0))
		if err != nil {
			t.Fatal(err)
		}
		head += line + "\n"
	}
	path, err := tree.InclusionProof(1)
	if err != nil {
		t.Fatal(err)
	}
	repaired, err := Build(b.Device, 1, repairedEntry, path, head)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := repaired.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Check(anchor); err != nil {
		t.Fatalf("expiry-only repair with renewed signatures and rebuilt tree: %v", err)
	}
	t.Log("request expiry repaired; request and envelope re-signed; rebuilt tree, checkpoint and proof accepted")
}
