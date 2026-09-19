package keyfile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func aKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestMarshalParseRoundTrip(t *testing.T) {
	pub, priv := aKey(t)
	raw, err := Marshal(priv, "a comment")
	if err != nil {
		t.Fatal(err)
	}
	got, comment, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(priv) {
		t.Error("the key changed in transit")
	}
	if comment != "a comment" {
		t.Errorf("comment = %q", comment)
	}
	if !got.Public().(ed25519.PublicKey).Equal(pub) {
		t.Error("public half differs")
	}
}

func TestParseRejections(t *testing.T) {
	_, priv := aKey(t)
	good, err := Marshal(priv, "c")
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":             nil,
		"not PEM":           []byte("hello"),
		"wrong PEM type":    pemOfType(t, "RSA PRIVATE KEY", []byte("x")),
		"truncated body":    pemOfType(t, pemType, []byte("openssh-key-v1\x00")),
		"wrong magic":       pemOfType(t, pemType, []byte("openssh-key-v2\x00rest")),
		"mismatched checks": withBrokenCheckints(t, good),
		"wrong key type":    withKeyType(t, good, "ssh-rsa"),
		"pub/priv disagree": withDifferentPublic(t, good),
	}
	for why, raw := range cases {
		if _, _, err := Parse(raw); err == nil {
			t.Errorf("accepted a key file that is %s", why)
		}
	}
}

// A key file is not a trusted input either: every prefix inside it is a length
// somebody could have chosen.
func TestTruncationAtEveryOffsetIsRefusedWithoutPanicking(t *testing.T) {
	_, priv := aKey(t)
	good, err := Marshal(priv, "c")
	if err != nil {
		t.Fatal(err)
	}
	body := decodeBody(t, good)
	for cut := 0; cut < len(body); cut++ {
		if _, _, err := parseBlob(body[:cut]); err == nil {
			t.Fatalf("accepted a blob truncated to %d bytes", cut)
		}
	}
}

func TestWriteThenRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.key")
	_, priv := aKey(t)

	if err := Write(path, priv, "device"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 600", mode)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("a temporary file was left behind: %v", entries)
	}

	got, comment, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(priv) || comment != "device" {
		t.Error("what came back is not what went in")
	}
}

// Overwriting a key file destroys an identity: `rotate` and self-`revoke` both
// need the key this would replace. It has to be a deliberate act.
func TestWriteRefusesToClobber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.key")
	_, first := aKey(t)
	_, second := aKey(t)

	if err := Write(path, first, "one"); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, second, "two"); err == nil {
		t.Fatal("silently replaced an existing key")
	}
	got, _, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(first) {
		t.Fatal("the original key was destroyed anyway")
	}
}

func TestReadRefusesALooseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.key")
	_, priv := aKey(t)
	if err := Write(path, priv, "device"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := Read(path)
	if err == nil {
		t.Fatal("read a key every user on the box can read")
	}
	if !strings.Contains(err.Error(), "644") {
		t.Errorf("the error should say what the mode is: %v", err)
	}
}

// -- helpers that damage a good file in one specific way ------------------

func pemOfType(t *testing.T, kind string, body []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: body})
}

func decodeBody(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	body, err := pemBody(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func rewrap(t *testing.T, body []byte) []byte {
	t.Helper()
	return pemOfType(t, pemType, body)
}

func withBrokenCheckints(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	body := decodeBody(t, pemBytes)
	// The private section is the last string in the blob; its first eight
	// bytes are the two check integers.
	index := bytes.LastIndex(body, []byte("ssh-ed25519"))
	start := index - 8 - 4 // back over the keytype length and the checkints
	binary.BigEndian.PutUint32(body[start:], 0xdeadbeef)
	return rewrap(t, body)
}

func withKeyType(t *testing.T, pemBytes []byte, keyType string) []byte {
	t.Helper()
	body := decodeBody(t, pemBytes)
	// Replace the *private* section's key type, leaving its length intact by
	// padding the name, so only the name itself is wrong.
	padded := (keyType + strings.Repeat("!", 11))[:11]
	index := bytes.LastIndex(body, []byte("ssh-ed25519"))
	copy(body[index:], padded)
	return rewrap(t, body)
}

func withDifferentPublic(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	body := decodeBody(t, pemBytes)
	other, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	// The public blob appears before the private section; change only that
	// copy, so the file claims a key its private half does not match.
	index := bytes.Index(body, []byte("ssh-ed25519"))
	copy(body[index+11+4:], other)
	return rewrap(t, body)
}
