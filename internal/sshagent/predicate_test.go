package sshagent

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"testing"
)

// identityKeyAndSignature is the signature SPEC §3.1 exists to refuse
// (D-072 (c)): the identity point as a key, R the identity and S = 0. The
// equation [0]B = O + [k]O holds whatever k is, so Go's crypto/ed25519 accepts
// it over every message -- a key anyone can sign anything with. The identity
// is not of order L, so NORN-ED25519-v1 refuses it.
func identityKeyAndSignature(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, sig := make([]byte, 32), make([]byte, 64)
	key[0], sig[0] = 1, 1
	if !ed25519.Verify(key, []byte("any message"), sig) {
		t.Fatal("crypto/ed25519 no longer accepts the identity's signature, so this test shows nothing")
	}
	return key, sig
}

// The check on what an agent returns is NORN-ED25519-v1, the one every
// verifier of the log applies: an agent offering the identity key and its
// signature puts nothing into the log.
func TestAnAgentSigningWithTheIdentityKeyIsRefused(t *testing.T) {
	key, sig := identityKeyAndSignature(t)
	socket := startFake(t, &fakeAgent{
		identities: func() []byte {
			payload := binary.BigEndian.AppendUint32([]byte{12}, 1)
			payload = append(payload, wireString(wireEd25519Blob(key))...)
			return append(payload, wireString([]byte("identity"))...)
		},
		sign: func(_, _ []byte) []byte {
			blob := append(wireString([]byte("ssh-ed25519")), wireString(sig)...)
			return append([]byte{14}, wireString(blob)...)
		},
	})
	client, err := Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	signer, err := client.Signer(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(nil, []byte("norn/entry/v1\nanything"), crypto.Hash(0)); err == nil {
		t.Error("the identity key's signature left the agent client")
	}
}
