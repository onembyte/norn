// Package trust parses and validates the trust file of SPEC.md §9: the only
// thing a verifier trusts a priori.
//
// Deterministic CBOR is authoritative here, not the TOML rendering: the
// fingerprint is taken over those bytes, so a field name or type that differs
// changes the fingerprint and the file must be refused.
package trust

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/note"
)

// Version is the only trust-file version this package speaks.
const Version = uint64(1)

// Crockford base32 omits I, L, O and U, so nothing in a fingerprint is
// confusable when read aloud or copied by hand.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// FingerprintBytes is 10: 80 bits, chosen so that an attacker who controls the
// delivery channel cannot grind a substitute file with a matching fingerprint.
const (
	FingerprintBytes = 10
	fingerprintGroup = 4
	netLen           = 16
	genesisHashLen   = 32
	maxNameLen       = 64
)

// ErrTrust reports a malformed or unusable trust anchor.
var ErrTrust = errors.New("trust file error")

func trustErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrTrust, fmt.Sprintf(format, args...))
}

// Witness is one entry of the witnesses array.
type Witness struct {
	Name string
	Key  string
	URL  string // optional; absent is the empty string
}

// Trust is a parsed trust file.
type Trust struct {
	Version     uint64
	Net         []byte
	Origin      string
	Name        string
	GenesisHash []byte
	LogKey      string
	LogURLs     []string
	Witnesses   []Witness
	Policy      string
	Anchor      map[string]any // optional
}

// OriginFor derives `norn/` + lowercase unpadded RFC 4648 base32 of net.
// Note the document also uses Crockford base32, in the fingerprint only: they
// are different alphabets and must not be interchanged.
func OriginFor(net []byte) (string, error) {
	if len(net) != netLen {
		return "", trustErrorf("net must be %d bytes", netLen)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(net)
	return "norn/" + strings.ToLower(encoded), nil
}

var knownKeys = map[string]bool{
	"version": true, "net": true, "origin": true, "name": true,
	"genesis_hash": true, "log_key": true, "log_urls": true,
	"witnesses": true, "policy": true, "anchor": true,
}

// Parse reads a trust file, enforcing the §9.1 shape.
func Parse(raw []byte) (*Trust, error) {
	value, err := cbor.Decode(raw)
	if err != nil {
		return nil, err
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, trustErrorf("trust file must be a map")
	}
	for key := range m {
		if !knownKeys[key] {
			return nil, trustErrorf("unknown field %q", key)
		}
	}
	t := &Trust{}
	if t.Version, ok = m["version"].(uint64); !ok {
		return nil, trustErrorf("version must be an unsigned integer")
	}
	if t.Net, ok = m["net"].([]byte); !ok {
		return nil, trustErrorf("net must be a byte string")
	}
	if t.Origin, ok = m["origin"].(string); !ok {
		return nil, trustErrorf("origin must be text")
	}
	if t.Name, ok = m["name"].(string); !ok {
		return nil, trustErrorf("name must be text")
	}
	if t.GenesisHash, ok = m["genesis_hash"].([]byte); !ok {
		return nil, trustErrorf("genesis_hash must be a byte string")
	}
	if t.LogKey, ok = m["log_key"].(string); !ok {
		return nil, trustErrorf("log_key must be text")
	}
	if t.Policy, ok = m["policy"].(string); !ok {
		return nil, trustErrorf("policy must be text")
	}
	urls, ok := m["log_urls"].([]any)
	if !ok {
		return nil, trustErrorf("log_urls must be an array")
	}
	for _, item := range urls {
		url, ok := item.(string)
		if !ok {
			return nil, trustErrorf("log_urls must contain text")
		}
		t.LogURLs = append(t.LogURLs, url)
	}
	witnesses, ok := m["witnesses"].([]any)
	if !ok {
		return nil, trustErrorf("witnesses must be an array")
	}
	for _, item := range witnesses {
		wm, ok := item.(map[string]any)
		if !ok {
			return nil, trustErrorf("each witness must be a map")
		}
		w := Witness{}
		for key, value := range wm {
			text, isText := value.(string)
			if !isText {
				return nil, trustErrorf("witness fields must be text")
			}
			switch key {
			case "name":
				w.Name = text
			case "key":
				w.Key = text
			case "url":
				w.URL = text
			default:
				return nil, trustErrorf("unknown witness field %q", key)
			}
		}
		t.Witnesses = append(t.Witnesses, w)
	}
	if anchor, present := m["anchor"]; present {
		if t.Anchor, ok = anchor.(map[string]any); !ok {
			return nil, trustErrorf("anchor must be a map")
		}
	}
	return t, nil
}

// Encode renders the trust file back to canonical CBOR. The fingerprint is
// taken over these bytes, so this must reproduce the file it was parsed from.
func (t *Trust) Encode() ([]byte, error) {
	urls := make([]any, 0, len(t.LogURLs))
	for _, u := range t.LogURLs {
		urls = append(urls, u)
	}
	witnesses := make([]any, 0, len(t.Witnesses))
	for _, w := range t.Witnesses {
		m := map[string]any{"name": w.Name, "key": w.Key}
		if w.URL != "" {
			m["url"] = w.URL
		}
		witnesses = append(witnesses, m)
	}
	doc := map[string]any{
		"version": t.Version, "net": t.Net, "origin": t.Origin, "name": t.Name,
		"genesis_hash": t.GenesisHash, "log_key": t.LogKey, "log_urls": urls,
		"witnesses": witnesses, "policy": t.Policy,
	}
	if t.Anchor != nil {
		doc["anchor"] = t.Anchor
	}
	return cbor.Encode(doc)
}

func parseKey(vkey string) (note.Verifier, error) { return note.ParseVerifierKey(vkey) }

// Validate applies every §9.1 rule. A file that fails any of them is not a
// usable anchor and MUST be refused.
func (t *Trust) Validate() error {
	if t.Version != Version {
		return trustErrorf("unsupported version %d", t.Version)
	}
	if len(t.Net) != netLen {
		return trustErrorf("net must be %d bytes", netLen)
	}
	origin, err := OriginFor(t.Net)
	if err != nil {
		return err
	}
	if t.Origin != origin {
		return trustErrorf("origin does not derive from net")
	}
	if len(t.GenesisHash) != genesisHashLen {
		return trustErrorf("genesis_hash must be %d bytes", genesisHashLen)
	}
	if n := len(t.Name); n < 1 || n > maxNameLen {
		return trustErrorf("name must be 1-%d bytes", maxNameLen)
	}
	logKey, err := parseKey(t.LogKey)
	if err != nil {
		return trustErrorf("log_key: %v", err)
	}
	// The note name binds the key to this network: a checkpoint signed by a key
	// named for another origin must not verify here.
	if logKey.Name != t.Origin {
		return trustErrorf("log_key is named %q, not the origin %q", logKey.Name, t.Origin)
	}
	if len(t.LogURLs) == 0 {
		return trustErrorf("at least one log URL is required")
	}
	for _, u := range t.LogURLs {
		if u == "" {
			return trustErrorf("log URLs must be non-empty")
		}
	}
	// With no witnesses the policy's quorum can never be met, so the anchor
	// could never accept a checkpoint.
	if len(t.Witnesses) == 0 {
		return trustErrorf("at least one witness is required")
	}
	seen := map[string]bool{}
	for _, w := range t.Witnesses {
		if w.Name == "" || w.Key == "" {
			return trustErrorf("each witness needs a name and a key")
		}
		if seen[w.Name] {
			return trustErrorf("duplicate witness name %q", w.Name)
		}
		seen[w.Name] = true
		if _, err := parseKey(w.Key); err != nil {
			return trustErrorf("witness %s: %v", w.Name, err)
		}
	}
	if !strings.Contains(t.Policy, "quorum") {
		return trustErrorf("policy must contain a quorum line")
	}
	if t.Anchor != nil {
		if _, ok := t.Anchor["type"].(string); !ok {
			return trustErrorf("anchor.type must be text")
		}
		if _, ok := t.Anchor["max_lag"].(uint64); !ok {
			return trustErrorf("anchor.max_lag must be an unsigned integer of seconds")
		}
		if _, ok := t.Anchor["mode"].(string); !ok {
			return trustErrorf("anchor.mode must be text")
		}
	}
	return nil
}

// Fingerprint renders 80 bits of SHA-256 over the canonical bytes, in Crockford
// base32, as four groups of four.
func (t *Trust) Fingerprint() (string, error) {
	raw, err := t.Encode()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	digest := sum[:FingerprintBytes]

	// 10 bytes is 80 bits, exactly 16 base32 characters, most-significant first.
	out := make([]byte, 0, 16+3)
	value := new(bigBits)
	value.set(digest)
	chars := value.base32(crockford)
	for i, c := range chars {
		if i > 0 && i%fingerprintGroup == 0 {
			out = append(out, '-')
		}
		out = append(out, c)
	}
	return string(out), nil
}

// bigBits renders an 80-bit value five bits at a time, most significant first,
// without pulling in math/big for ten bytes.
type bigBits struct{ b [FingerprintBytes]byte }

func (v *bigBits) set(digest []byte) { copy(v.b[:], digest) }

func (v *bigBits) base32(alphabet string) []byte {
	total := len(v.b) * 8
	out := make([]byte, 0, total/5)
	for offset := 0; offset+5 <= total; offset += 5 {
		var chunk uint16
		for i := 0; i < 5; i++ {
			bit := offset + i
			byteAt := v.b[bit/8]
			chunk = chunk<<1 | uint16((byteAt>>(7-uint(bit%8)))&1)
		}
		out = append(out, alphabet[chunk])
	}
	return out
}
