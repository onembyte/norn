package keyfile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
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

// Agreement among stored copies cannot prove that any of them matches the seed.
func TestThePublicCopiesMustAgreeWithTheSeed(t *testing.T) {
	_, keyA := aKey(t)
	pubB, keyB := aKey(t)
	t.Run("three matching copies with another seed", func(t *testing.T) {
		raw, err := Marshal(keyB, "seed mismatch")
		if err != nil {
			t.Fatal(err)
		}
		body := decodeBody(t, raw)
		index := bytes.Index(body, keyB)
		if index < 0 {
			t.Fatal("the marshalled file contains no private key")
		}
		copy(body[index:index+ed25519.SeedSize], keyA.Seed())
		if _, _, err := Parse(rewrap(t, body)); err == nil {
			t.Fatal("accepted key A's seed with key B's three public copies")
		}
	})
	for _, which := range []string{"stored half", "inner public", "declared public"} {
		t.Run(which, func(t *testing.T) {
			raw, err := Marshal(keyA, "public mismatch")
			if err != nil {
				t.Fatal(err)
			}
			body := decodeBody(t, raw)
			index := bytes.Index(body, keyA)
			if index < 0 {
				t.Fatal("the marshalled file contains no private key")
			}
			switch which {
			case "stored half":
				index += ed25519.SeedSize
			case "declared public":
				index = bytes.Index(body, keyA[ed25519.SeedSize:])
			case "inner public":
				first := bytes.Index(body, keyA[ed25519.SeedSize:])
				index = first + ed25519.PublicKeySize + bytes.Index(body[first+ed25519.PublicKeySize:], keyA[ed25519.SeedSize:])
			}
			copy(body[index:index+ed25519.PublicKeySize], pubB)
			if _, _, err := Parse(rewrap(t, body)); err == nil {
				t.Fatalf("accepted a %s that disagrees with the seed", which)
			}
		})
	}
}

// Publication must remain exclusive even if a destination appears after Stat.
func TestPublishingAKeyNeverReplacesAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	before := []byte("the existing identity")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	err := publishKey(path, []byte("a replacement identity"), (*os.File).Sync)
	if err == nil {
		t.Error("publication replaced a destination created after the existence check")
	} else if !strings.Contains(err.Error(), "already exists; remove it deliberately") {
		t.Errorf("lost the operator's existing-file error: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("the existing bytes were changed")
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatal("publication left a temporary file behind")
	}
}

// The sync seam observes when bytes and names become visible, so the test can
// distinguish flushing the temporary from flushing the published directory.
func TestPublishingAKeySyncsTheBytesBeforeTheDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	data := []byte("a new identity")
	calls := 0
	syncFile := func(f *os.File) error {
		calls++
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if info.IsDir() {
			if calls != 2 {
				t.Error("the directory was synced before the key bytes")
			}
			files, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				return err
			}
			if len(files) != 1 || files[0].Name() != "key" {
				t.Error("the directory was synced before removing the temporary")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if string(raw) != string(data) {
				t.Error("the published bytes changed")
			}
		} else {
			if calls != 1 {
				t.Error("the key bytes were not synced first")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Error("the final name existed before the key bytes were synced")
			}
			raw, err := os.ReadFile(f.Name())
			if err != nil {
				return err
			}
			if string(raw) != string(data) {
				t.Error("the temporary was synced before all bytes were written")
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("temporary mode = %o, want 600", info.Mode().Perm())
			}
		}
		return f.Sync()
	}
	if err := publishKey(path, data, syncFile); err != nil {
		t.Fatal(err)
	}
	want := 2 // the file, then the directory
	if runtime.GOOS == "windows" {
		want = 1 // Windows cannot sync a directory handle
	}
	if calls != want {
		t.Fatalf("publication made %d sync calls, want %d", calls, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("published mode = %o, want 600", info.Mode().Perm())
	}
}
