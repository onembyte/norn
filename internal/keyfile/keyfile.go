// Package keyfile reads and writes Ed25519 keys in the OpenSSH private-key
// format ("openssh-key-v1"), unencrypted.
//
// Norn invents no key format (§16.3), and this is the reason
// the promise survives contact with a daemon: `nornd` on a device signs
// `rotate` and self-`revoke` entries with a key nobody can type a passphrase
// for at boot, so that key lives in a file. Using OpenSSH's format rather than
// one of Norn's own means `ssh-keygen` can make it, `ssh-add` can load it into
// an agent unchanged -- tier 0 becomes tier 1 with no conversion -- and the
// tests can check both directions against the real tools.
//
// Encrypted keys are refused, on purpose. Decrypting one means bcrypt-pbkdf, a
// cryptographic primitive Norn would have to import or hand-roll, and a
// passphrase prompt inside every command. A passphrase-protected key belongs in
// an agent, which is where `ssh-add` puts it after prompting once.
package keyfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/onembyte/norn/internal/sshwire"

	"github.com/onembyte/norn/internal/durable"
)

const (
	pemType = "OPENSSH PRIVATE KEY"
	magic   = "openssh-key-v1\x00"
	keyType = "ssh-ed25519"
	// Cipher "none" still pads the private section to an 8-byte boundary.
	blockSize = 8
	// MaxFileBytes caps a key file. An Ed25519 key is a few hundred bytes.
	MaxFileBytes = 64 << 10
)

// ErrEncrypted reports a passphrase-protected key, which belongs in an agent.
var ErrEncrypted = errors.New("keyfile: the key is encrypted")

// Generate makes a new Ed25519 key.
func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Marshal encodes a key in the OpenSSH private-key format, unencrypted.
func Marshal(key ed25519.PrivateKey, comment string) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("keyfile: private key is %d bytes, want %d",
			len(key), ed25519.PrivateKeySize)
	}
	public := key.Public().(ed25519.PublicKey)

	publicBlob := sshwire.AppendString(nil, []byte(keyType))
	publicBlob = sshwire.AppendString(publicBlob, public)

	// The two check integers are equal in a decrypted section; a decrypter
	// compares them to tell a right passphrase from a wrong one.
	var check [4]byte
	if _, err := rand.Read(check[:]); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	private := append(append([]byte(nil), check[:]...), check[:]...)
	private = sshwire.AppendString(private, []byte(keyType))
	private = sshwire.AppendString(private, public)
	private = sshwire.AppendString(private, key)
	private = sshwire.AppendString(private, []byte(comment))
	for i := byte(1); len(private)%blockSize != 0; i++ {
		private = append(private, i)
	}

	blob := append([]byte(nil), magic...)
	blob = sshwire.AppendString(blob, []byte("none")) // cipher
	blob = sshwire.AppendString(blob, []byte("none")) // kdf
	blob = sshwire.AppendString(blob, nil)            // kdf options
	blob = sshwire.AppendUint32(blob, 1)              // one key
	blob = sshwire.AppendString(blob, publicBlob)
	blob = sshwire.AppendString(blob, private)

	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: blob}), nil
}

// Parse decodes an unencrypted OpenSSH private key.
func Parse(raw []byte) (ed25519.PrivateKey, string, error) {
	body, err := pemBody(raw)
	if err != nil {
		return nil, "", err
	}
	return parseBlob(body)
}

func pemBody(raw []byte) ([]byte, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("keyfile: not a PEM file")
	}
	if block.Type != pemType {
		return nil, fmt.Errorf("keyfile: PEM type is %q, want %q", block.Type, pemType)
	}
	return block.Bytes, nil
}

func parseBlob(blob []byte) (ed25519.PrivateKey, string, error) {
	if len(blob) < len(magic) || string(blob[:len(magic)]) != magic {
		return nil, "", errors.New("keyfile: not an openssh-key-v1 blob")
	}
	rest := blob[len(magic):]

	cipher, rest, err := sshwire.String(rest)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: cipher: %w", err)
	}
	kdf, rest, err := sshwire.String(rest)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: kdf: %w", err)
	}
	if _, rest, err = sshwire.String(rest); err != nil { // kdf options
		return nil, "", fmt.Errorf("keyfile: kdf options: %w", err)
	}
	if string(cipher) != "none" || string(kdf) != "none" {
		return nil, "", fmt.Errorf("%w (cipher %q, kdf %q): load it into an ssh-agent "+
			"with `ssh-add` and let Norn use the agent", ErrEncrypted, cipher, kdf)
	}

	count, rest, err := sshwire.Uint32(rest)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: key count: %w", err)
	}
	if count != 1 {
		return nil, "", fmt.Errorf("keyfile: the file holds %d keys, want 1", count)
	}

	publicBlob, rest, err := sshwire.String(rest)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: public key: %w", err)
	}
	declared, err := publicFromBlob(publicBlob)
	if err != nil {
		return nil, "", err
	}
	private, _, err := sshwire.String(rest)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: private section: %w", err)
	}

	first, private, err := sshwire.Uint32(private)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: check integer: %w", err)
	}
	second, private, err := sshwire.Uint32(private)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: check integer: %w", err)
	}
	if first != second {
		// In an encrypted file this is how a wrong passphrase looks; in an
		// unencrypted one it means the bytes are damaged.
		return nil, "", errors.New("keyfile: the check integers differ; the file is damaged")
	}

	innerType, private, err := sshwire.String(private)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: key type: %w", err)
	}
	if string(innerType) != keyType {
		return nil, "", fmt.Errorf("keyfile: key type is %q, and §3 allows only %q",
			innerType, keyType)
	}
	innerPublic, private, err := sshwire.String(private)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: public half: %w", err)
	}
	secret, private, err := sshwire.String(private)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: private half: %w", err)
	}
	comment, _, err := sshwire.String(private)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: comment: %w", err)
	}

	if len(secret) != ed25519.PrivateKeySize {
		return nil, "", fmt.Errorf("keyfile: private key is %d bytes, want %d",
			len(secret), ed25519.PrivateKeySize)
	}
	key := ed25519.PrivateKey(secret)
	derived := ed25519.NewKeyFromSeed(secret[:ed25519.SeedSize]).Public().(ed25519.PublicKey)

	// Three copies of the public key travel in this file, and each must agree
	// with the key derived from the seed, not merely with the other copies.
	// A file whose halves disagree is damaged or crafted, and signing with it
	// would put an unexpected identity into the log.
	if !bytes.Equal(secret[ed25519.SeedSize:], derived) ||
		!bytes.Equal(innerPublic, derived) || !declared.Equal(derived) {
		return nil, "", errors.New("keyfile: the public and private halves disagree")
	}
	return key, string(comment), nil
}

func publicFromBlob(blob []byte) (ed25519.PublicKey, error) {
	algorithm, rest, err := sshwire.String(blob)
	if err != nil {
		return nil, fmt.Errorf("keyfile: public key algorithm: %w", err)
	}
	if string(algorithm) != keyType {
		return nil, fmt.Errorf("keyfile: public key is %q, and §3 allows only %q",
			algorithm, keyType)
	}
	public, _, err := sshwire.String(rest)
	if err != nil {
		return nil, fmt.Errorf("keyfile: public key body: %w", err)
	}
	if len(public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("keyfile: public key is %d bytes, want %d",
			len(public), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(public), nil
}

// Read loads a key from disk, refusing one other users can read.
func Read(path string) (ed25519.PrivateKey, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, "", fmt.Errorf("keyfile: %s is mode %o; a signing key must not be "+
			"readable by other users (chmod 600)", path, mode)
	}
	if info.Size() > MaxFileBytes {
		return nil, "", fmt.Errorf("keyfile: %s is %d bytes, over the %d cap",
			path, info.Size(), MaxFileBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("keyfile: %w", err)
	}
	return Parse(raw)
}

// Write saves a key with mode 0600, refusing to replace an existing file.
//
// The refusal is the point: overwriting a device key destroys the identity that
// `rotate` and self-`revoke` depend on, and a key lost that way cannot be
// recovered from the log.
func Write(path string, key ed25519.PrivateKey, comment string) error {
	raw, err := Marshal(key, comment)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("keyfile: %s already exists; remove it deliberately if you "+
			"mean to replace that identity", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("keyfile: %w", err)
	}

	return publishKey(path, raw, (*os.File).Sync)
}

// publishKey is durable.Publish with this package's words on the one error
// an operator will meet (H4-d folds the twin that lived here into durable).
func publishKey(path string, raw []byte, syncFile func(*os.File) error) error {
	err := durable.PublishWith(path, raw, 0o600, syncFile)
	if errors.Is(err, durable.ErrExists) {
		return fmt.Errorf("keyfile: %s already exists; remove it deliberately if you mean to replace that identity", path)
	}
	if err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	return nil
}
