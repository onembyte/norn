// Package sshagent speaks the small part of the ssh-agent protocol Norn needs:
// list the Ed25519 keys an agent holds, and ask it to sign a message.
//
// Why an agent at all: it is the one abstraction under which a Tillitis TKey,
// a YubiKey behind gpg-agent, a password manager and a software key all look
// identical, so Norn needs no key store of its own and invents no key format
// (§16.3). For Ed25519 an agent returns a plain Ed25519
// signature, which is exactly what §4.2 wants.
//
// Why not golang.org/x/crypto/ssh/agent: measured at five modules
// (crypto, net, sys, term, text) and the whole SSH transport, for a four
// message protocol -- the same trade as D-049. The risk of writing it instead
// is being wrong about the wire format, so the tests drive a **real OpenSSH
// ssh-agent**, not only the fake. The fake is for what a real agent will not do
// on request: lie, truncate, or announce a gigabyte.
//
// Nothing here knows what Norn is. An agent holds keys; deciding which key
// matters is the caller's business.
package sshagent

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/onembyte/norn/internal/ed25519v1"
	"github.com/onembyte/norn/internal/sshwire"
)

// Message numbers from the ssh-agent protocol.
const (
	msgFailure           = 5
	msgRequestIdentities = 11
	msgIdentitiesAnswer  = 12
	msgSignRequest       = 13
	msgSignResponse      = 14
)

// KeyType is the only algorithm Norn signs with (SPEC §3).
const KeyType = "ssh-ed25519"

// SocketEnv names the environment variable every agent implementation sets.
const SocketEnv = "SSH_AUTH_SOCK"

// MaxResponseBytes caps a single agent response. An agent is not a trusted
// peer: the length it announces must not become an allocation.
const MaxResponseBytes = 256 << 10

// ErrNoAgent reports that no agent is configured in the environment.
var ErrNoAgent = errors.New("sshagent: no agent")

// Key is one Ed25519 identity an agent holds.
type Key struct {
	Public  ed25519.PublicKey
	Comment string
}

// Client is a connection to an agent. It is not safe for concurrent use: the
// protocol is one request and one response at a time on the same socket.
type Client struct {
	conn net.Conn
}

// Open connects to the agent named by SSH_AUTH_SOCK.
func Open() (*Client, error) {
	socket := os.Getenv(SocketEnv)
	if socket == "" {
		return nil, fmt.Errorf("%w: %s is not set", ErrNoAgent, SocketEnv)
	}
	return Dial(socket)
}

// Dial connects to an agent listening on a Unix socket.
func Dial(socket string) (*Client, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("sshagent: %w", err)
	}
	return &Client{conn: conn}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Keys lists the agent's Ed25519 identities.
//
// Keys of other types are skipped rather than refused: an agent holding the
// user's RSA login key alongside a Norn signer is the normal case, and failing
// there would make Norn unusable on a real workstation.
func (c *Client) Keys() ([]Key, error) {
	payload, err := c.request([]byte{msgRequestIdentities})
	if err != nil {
		return nil, err
	}
	if payload[0] != msgIdentitiesAnswer {
		return nil, fmt.Errorf("sshagent: answer %d to a request for identities", payload[0])
	}
	body := payload[1:]
	if len(body) < 4 {
		return nil, errors.New("sshagent: truncated identities answer")
	}
	count := binary.BigEndian.Uint32(body[:4])
	body = body[4:]

	var keys []Key
	for i := uint32(0); i < count; i++ {
		blob, rest, err := sshwire.String(body)
		if err != nil {
			return nil, fmt.Errorf("sshagent: identity %d: %w", i, err)
		}
		comment, rest, err := sshwire.String(rest)
		if err != nil {
			return nil, fmt.Errorf("sshagent: identity %d comment: %w", i, err)
		}
		body = rest
		if public, ok := ed25519FromBlob(blob); ok {
			keys = append(keys, Key{Public: public, Comment: string(comment)})
		}
	}
	return keys, nil
}

// Signer returns a crypto.Signer backed by the agent's copy of public.
//
// The key must be one the agent actually holds: asking for a signature by a key
// it does not have fails later and less clearly.
func (c *Client) Signer(public ed25519.PublicKey) (crypto.Signer, error) {
	keys, err := c.Keys()
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if key.Public.Equal(public) {
			return &Signer{client: c, public: key.Public}, nil
		}
	}
	return nil, fmt.Errorf("sshagent: the agent holds no key %x", public[:8])
}

// Signer signs through an agent. It satisfies crypto.Signer, so an entry
// cannot tell it apart from a key in memory.
type Signer struct {
	client *Client
	public ed25519.PublicKey
}

// Public returns the key this signer signs with.
func (s *Signer) Public() crypto.PublicKey { return s.public }

// Sign asks the agent for a signature over message, and verifies it before
// returning it.
//
// The verification is the point. An agent is a separate process -- sometimes a
// piece of hardware, sometimes a program from a different vendor -- and a
// signature that does not verify must fail here rather than in the log, where
// it would be a Norn bug in somebody else's replay.
func (s *Signer) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, fmt.Errorf("sshagent: pure Ed25519 signs the message whole, "+
			"and %v was requested", opts.HashFunc())
	}

	request := []byte{msgSignRequest}
	request = sshwire.AppendString(request, ed25519Blob(s.public))
	request = sshwire.AppendString(request, message)
	request = binary.BigEndian.AppendUint32(request, 0) // flags: none for Ed25519

	payload, err := s.client.request(request)
	if err != nil {
		return nil, err
	}
	if payload[0] == msgFailure {
		return nil, errors.New("sshagent: the agent refused to sign")
	}
	if payload[0] != msgSignResponse {
		return nil, fmt.Errorf("sshagent: answer %d to a signing request", payload[0])
	}

	blob, _, err := sshwire.String(payload[1:])
	if err != nil {
		return nil, fmt.Errorf("sshagent: signature: %w", err)
	}
	algorithm, rest, err := sshwire.String(blob)
	if err != nil {
		return nil, fmt.Errorf("sshagent: signature algorithm: %w", err)
	}
	if string(algorithm) != KeyType {
		return nil, fmt.Errorf("sshagent: the agent signed with %q, want %q", algorithm, KeyType)
	}
	signature, _, err := sshwire.String(rest)
	if err != nil {
		return nil, fmt.Errorf("sshagent: signature body: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("sshagent: signature is %d bytes, want %d",
			len(signature), ed25519.SignatureSize)
	}
	if !ed25519v1.Verify(s.public, message, signature) {
		return nil, errors.New("sshagent: the agent returned a signature that does not verify")
	}
	return signature, nil
}

// request writes one message and reads one response.
func (c *Client) request(payload []byte) ([]byte, error) {
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	if _, err := c.conn.Write(append(frame, payload...)); err != nil {
		return nil, fmt.Errorf("sshagent: writing to the agent: %w", err)
	}
	var size [4]byte
	if _, err := io.ReadFull(c.conn, size[:]); err != nil {
		return nil, fmt.Errorf("sshagent: reading from the agent: %w", err)
	}
	return c.readResponse(size[:])
}

// readResponse reads a frame whose length prefix has already been read.
func (c *Client) readResponse(size []byte) ([]byte, error) {
	length := binary.BigEndian.Uint32(size)
	if length == 0 {
		return nil, errors.New("sshagent: empty response")
	}
	if length > MaxResponseBytes {
		return nil, fmt.Errorf("sshagent: the agent announced %d bytes, over the %d cap",
			length, MaxResponseBytes)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, fmt.Errorf("sshagent: short response: %w", err)
	}
	return payload, nil
}

func ed25519Blob(public ed25519.PublicKey) []byte {
	blob := sshwire.AppendString(nil, []byte(KeyType))
	return sshwire.AppendString(blob, public)
}

// ed25519FromBlob reads a public key blob, reporting whether it is Ed25519.
func ed25519FromBlob(blob []byte) (ed25519.PublicKey, bool) {
	algorithm, rest, err := sshwire.String(blob)
	if err != nil || string(algorithm) != KeyType {
		return nil, false
	}
	public, _, err := sshwire.String(rest)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(public), true
}
