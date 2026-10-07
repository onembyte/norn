// Package wgkey handles WireGuard keys: the X25519 pair a device enrols.
//
// These keys never sign anything (SPEC §3). Norn only ever needs the public
// half, to put in an `enroll` request and, later, in the peer table -- but the
// public half usually has to be derived from the private key sitting in
// /etc/wireguard, because `wg show` needs a configured interface and `norn
// enroll` runs before there is one.
//
// The arithmetic is crypto/ecdh's, and the tests pin it to RFC 7748's own
// vectors. Deriving a public key wrongly would enrol a key the device cannot
// handshake with, and nothing else in Norn would notice: the entry would be
// perfectly valid and the tunnel would simply never come up.
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// KeyLen is the length of a WireGuard key, public or private.
const KeyLen = 32

// MaxFileBytes caps a key file; a base64 key is 45 bytes with its newline.
const MaxFileBytes = 4 << 10

// Public derives the public key of a WireGuard private key.
func Public(private []byte) ([]byte, error) {
	if len(private) != KeyLen {
		return nil, fmt.Errorf("wgkey: private key is %d bytes, want %d", len(private), KeyLen)
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("wgkey: %w", err)
	}
	return key.PublicKey().Bytes(), nil
}

// Generate makes a new WireGuard key pair.
func Generate() (private, public []byte, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("wgkey: %w", err)
	}
	return key.Bytes(), key.PublicKey().Bytes(), nil
}

// Format encodes a key the way WireGuard does: standard base64, padded.
func Format(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// Parse decodes a base64 key, ignoring surrounding whitespace.
//
// `wg genkey > wg0.key` leaves a trailing newline and people paste keys with
// spaces around them; the bytes are what matter.
func Parse(text string) ([]byte, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, errors.New("wgkey: empty key")
	}
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("wgkey: not base64: %w", err)
	}
	if len(raw) != KeyLen {
		return nil, fmt.Errorf("wgkey: key is %d bytes, want %d", len(raw), KeyLen)
	}
	return raw, nil
}

// ReadPrivate loads a WireGuard private key file, refusing one other users can
// read. wg-quick refuses such a file too, and for the same reason.
func ReadPrivate(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("wgkey: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("wgkey: %s is mode %o; a WireGuard private key must not "+
			"be readable by other users (chmod 600)", path, mode)
	}
	if info.Size() > MaxFileBytes {
		return nil, fmt.Errorf("wgkey: %s is %d bytes, which is not a key", path, info.Size())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wgkey: %w", err)
	}
	return Parse(string(raw))
}

// WritePrivate saves a private key with mode 0600, refusing to replace one.
//
// The trailing newline is what `wg pubkey < file` expects, so a key Norn
// generated stays usable with the ordinary WireGuard tools.
func WritePrivate(path string, private []byte) error {
	if len(private) != KeyLen {
		return fmt.Errorf("wgkey: private key is %d bytes, want %d", len(private), KeyLen)
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("wgkey: %s already exists; remove it deliberately if you mean "+
			"to replace that key", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("wgkey: %w", err)
	}

	return publishKey(path, []byte(Format(private)+"\n"), (*os.File).Sync)
}

func publishKey(path string, raw []byte, syncFile func(*os.File) error) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".norn-wg-*")
	if err != nil {
		return fmt.Errorf("wgkey: %w", err)
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("wgkey: %w", err)
	}
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return fmt.Errorf("wgkey: %w", err)
	}
	// Flush the bytes before publishing a name that another process can read.
	if err := syncFile(temp); err != nil {
		temp.Close()
		return fmt.Errorf("wgkey: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("wgkey: %w", err)
	}
	// Linking is exclusive: a name created after Stat must never be replaced.
	if err := os.Link(temp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("wgkey: %s already exists; remove it deliberately if you mean to replace that key", path)
		}
		return fmt.Errorf("wgkey: %w", err)
	}
	// Remove the temporary before flushing the directory, so both name changes
	// survive together with the already-synced key bytes.
	if err := os.Remove(temp.Name()); err != nil {
		return fmt.Errorf("wgkey: %w", err)
	}
	// Windows cannot open a directory for writing and orders its metadata
	// itself, so the directory sync is skipped there, as internal/durable does.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("wgkey: %w", err)
	}
	defer dir.Close()
	if err := syncFile(dir); err != nil {
		return fmt.Errorf("wgkey: %w", err)
	}
	return nil
}
