package wgkey

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// RFC 7748 §6.1. The X25519 base-point multiplication is the one piece of
// arithmetic here, and these vectors are the specification's own -- deriving a
// public key wrongly would enrol a key the device cannot handshake with, and
// nothing in Norn would notice.
const (
	alicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	alicePublic  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	bobPrivate   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	bobPublic    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
)

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPublicMatchesRFC7748(t *testing.T) {
	for _, pair := range []struct{ private, public string }{
		{alicePrivate, alicePublic},
		{bobPrivate, bobPublic},
	} {
		got, err := Public(fromHex(t, pair.private))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != pair.public {
			t.Errorf("Public(%s…) = %x, want %s", pair.private[:8], got, pair.public)
		}
	}
}

func TestPublicRejectsTheWrongLength(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := Public(make([]byte, n)); err == nil {
			t.Errorf("accepted a %d-byte private key", n)
		}
	}
}

// WireGuard's own encoding: standard base64 of the raw 32 bytes, which is what
// `wg genkey` prints and what a wg0.conf carries.
func TestBase64RoundTrip(t *testing.T) {
	raw := fromHex(t, alicePrivate)
	encoded := Format(raw)
	if len(encoded) != 44 || !strings.HasSuffix(encoded, "=") {
		t.Errorf("encoded = %q, want 44 characters of padded base64", encoded)
	}
	if want := base64.StdEncoding.EncodeToString(raw); encoded != want {
		t.Errorf("encoded = %q, want %q", encoded, want)
	}
	back, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(back) != alicePrivate {
		t.Errorf("round trip = %x", back)
	}
}

func TestParseRejections(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"not base64":      "this is not base64!!!!!!!!!!!!!!!!!!!!!!!!!!",
		"too short":       base64.StdEncoding.EncodeToString(make([]byte, 31)),
		"too long":        base64.StdEncoding.EncodeToString(make([]byte, 33)),
		"hex not base64":  alicePrivate,
		"unpadded base64": strings.TrimRight(base64.StdEncoding.EncodeToString(make([]byte, 32)), "="),
	}
	for why, value := range cases {
		if _, err := Parse(value); err == nil {
			t.Errorf("accepted a key that is %s", why)
		}
	}
}

func TestParseToleratesSurroundingWhitespace(t *testing.T) {
	// `wg genkey > file` leaves a trailing newline, and people paste with
	// spaces. The bytes are what matter.
	encoded := Format(fromHex(t, bobPrivate))
	for _, value := range []string{encoded + "\n", " " + encoded + " \r\n"} {
		got, err := Parse(value)
		if err != nil {
			t.Fatalf("Parse(%q): %v", value, err)
		}
		if hex.EncodeToString(got) != bobPrivate {
			t.Errorf("Parse(%q) = %x", value, got)
		}
	}
}

func TestGenerateProducesAUsablePair(t *testing.T) {
	private, public, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(private) != KeyLen || len(public) != KeyLen {
		t.Fatalf("lengths are %d and %d", len(private), len(public))
	}
	derived, err := Public(private)
	if err != nil {
		t.Fatal(err)
	}
	if string(derived) != string(public) {
		t.Error("the public key does not belong to the private key")
	}

	other, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if string(other) == string(private) {
		t.Fatal("two generated keys are identical")
	}
}

func TestReadPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.key")
	encoded := Format(fromHex(t, alicePrivate))
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != alicePrivate {
		t.Errorf("got %x", got)
	}
}

// A WireGuard private key is a private key: the same rule as a Norn key file.
func TestReadPrivateRefusesALooseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg0.key")
	if err := os.WriteFile(path, []byte(Format(fromHex(t, alicePrivate))), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ReadPrivate(path)
	if err == nil {
		t.Fatal("read a WireGuard key every user on the box can read")
	}
	if !strings.Contains(err.Error(), "644") {
		t.Errorf("the error should name the mode: %v", err)
	}
}

func TestWritePrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg.key")
	private, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(path, private); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 600", mode)
	}
	if err := WritePrivate(path, private); err == nil {
		t.Error("silently replaced an existing WireGuard key")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// `wg pubkey < file` must work on what we wrote: base64 and a newline.
	if !strings.HasSuffix(string(raw), "\n") {
		t.Error("no trailing newline; `wg pubkey < file` expects one")
	}
	back, err := Parse(string(raw))
	if err != nil || string(back) != string(private) {
		t.Errorf("what was written does not parse back: %v", err)
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
