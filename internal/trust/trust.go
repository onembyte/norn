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
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/ed25519v1"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
)

// MaxTrustBytes bounds a trust file: keys, urls, a witness list and a policy
// of at most 4096 bytes. Stated here rather than inherited from §4.0, whose
// cap is §6's entry framing (§9.1).
const MaxTrustBytes = 1 << 16

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
	Name   string
	Key    string
	URL    string // opaque optional text; an explicitly present empty value is allowed
	HasURL bool   // preserves the distinction between an absent URL and empty text
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
	value, err := cbor.DecodeWithin(raw, MaxTrustBytes)
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
				w.HasURL = true
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
		if w.HasURL || w.URL != "" {
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
	// §3.1 item 2: a key is admitted only as a valid point.
	if !ed25519v1.ValidPoint(logKey.Public) {
		return trustErrorf("log_key is not a valid point (SPEC §3.1)")
	}
	// The log signs notes; a witness signs cosignatures. They are different
	// algorithms with different key ids (c2sp.org/tlog-cosignature), and a
	// file that mixed them up would name keys nobody can use.
	if logKey.IsCosigner() {
		return trustErrorf("log_key is a cosignature key; the log signs checkpoints, " +
			"not cosignatures")
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
		if n := len(w.Name); n < 1 || n > maxNameLen {
			// Bounded like the network name. The reference implementation
			// capped this and Go did not, and no file in the suite was long
			// enough to tell (cold gate run 8, D22).
			return trustErrorf("a witness name must be 1-%d bytes", maxNameLen)
		}
		if w.Key == "" {
			return trustErrorf("each witness needs a name and a key")
		}
		if seen[w.Name] {
			return trustErrorf("duplicate witness name %q", w.Name)
		}
		seen[w.Name] = true
		witnessKey, err := parseKey(w.Key)
		if err != nil {
			return trustErrorf("witness %s: %v", w.Name, err)
		}
		if !ed25519v1.ValidPoint(witnessKey.Public) {
			return trustErrorf("witness %s's key is not a valid point (SPEC §3.1)", w.Name)
		}
		if !witnessKey.IsCosigner() {
			return trustErrorf("witness %s publishes a note key; a witness key is a "+
				"cosignature key (c2sp.org/tlog-cosignature)", w.Name)
		}
	}
	parsed, err := policy.Parse(t.Policy)
	if err != nil {
		return trustErrorf("policy: %v", err)
	}
	// The two lists must agree. `witnesses` is where a node learns a witness's
	// name and address; `policy` is where it learns whether that witness
	// counts. A file where they differ configures a quorum over parties the
	// node cannot reach, or lists parties nothing requires -- either way the
	// operator believes they set something they did not.
	//
	// Correspondence is about *which* names appear, not how many times: the
	// uniqueness rule above owns multiplicity. This loop used to strike each
	// name off as it matched, which meant a file listing one witness twice was
	// refused here -- so an implementation missing the uniqueness rule
	// entirely was saved by this one, and the mutation proving that is what
	// made the two separable (cold gate run 7, J12).
	named := map[string]string{}
	for _, w := range parsed.Witnesses {
		named[w.Name] = w.Key
	}
	covered := map[string]bool{}
	for _, w := range t.Witnesses {
		key, ok := named[w.Name]
		if !ok {
			return trustErrorf("witness %s is listed but the policy never names it", w.Name)
		}
		if key != w.Key {
			return trustErrorf("witness %s has one key in `witnesses` and another in the policy",
				w.Name)
		}
		covered[w.Name] = true
	}
	for name := range named {
		if !covered[name] {
			return trustErrorf("the policy names witness %s, which `witnesses` does not list", name)
		}
	}
	// The policy's `log` line is informational -- Norn takes the log key from
	// `log_key` (§9.1) -- but a file whose two halves name different logs is
	// the same operator error the witness correspondence rule exists to catch.
	for _, l := range parsed.Logs {
		if l.Key != t.LogKey {
			return trustErrorf("the policy's log line names %q and log_key is %q; "+
				"a trust file names one log", l.Key, t.LogKey)
		}
	}
	if t.Anchor != nil {
		if len(t.Anchor) != 3 {
			return trustErrorf("anchor must contain exactly type, max_lag and mode")
		}
		for key := range t.Anchor {
			if key != "type" && key != "max_lag" && key != "mode" {
				return trustErrorf("unknown anchor field %q", key)
			}
		}
		// An unknown `type` is ignorable -- anchoring is advisory (D-009), so a
		// reader that cannot check it simply does not -- but an unknown `mode`
		// is not: guessing what an unrecognised enforcement mode means is how a
		// node enforces something nobody asked for.
		if mode, _ := t.Anchor["mode"].(string); mode != "advisory" {
			return trustErrorf("anchor.mode %q is not one this version defines", mode)
		}
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

// NetFromOrigin is the inverse of OriginFor.
//
// A device enrolling for the first time has no trust file yet -- it imports one
// only after it has been enrolled -- so the only way it can name its network is
// the origin string, which is public and printable. Case is accepted either
// way: base32's alphabet has one case, and an operator reading an origin off a
// screen should not have to care.
func NetFromOrigin(origin string) ([]byte, error) {
	const prefix = "norn/"
	if !strings.HasPrefix(origin, prefix) {
		return nil, trustErrorf("an origin starts with %q: %q", prefix, origin)
	}
	encoded := strings.ToUpper(strings.TrimPrefix(origin, prefix))
	net, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		return nil, trustErrorf("origin is not base32: %v", err)
	}
	if len(net) != netLen {
		return nil, trustErrorf("origin decodes to %d bytes, want %d", len(net), netLen)
	}
	return net, nil
}

// ToTOML renders the anchor as §9.2's human-readable form.
//
// The CBOR stays authoritative: this exists so an operator can read a trust
// file, and above all so they can compare the **fingerprint** out of band
// before trusting it. Its shape is fixed by the suite's `trust.toml`, which the
// reference implementation produces — so the two renderings are held to the
// same bytes rather than each to its own author's taste.
func (t *Trust) ToTOML() (string, error) {
	fingerprint, err := t.Fingerprint()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Norn trust file for %s\n", t.Name)
	fmt.Fprintf(&b, "# fingerprint = %s\n", fingerprint)
	b.WriteString("# Compare the fingerprint out of band before trusting this file.\n\n")
	fmt.Fprintf(&b, "version      = %d\n", t.Version)
	fmt.Fprintf(&b, "net          = %s\n", tomlString(hex.EncodeToString(t.Net)))
	fmt.Fprintf(&b, "origin       = %s\n", tomlString(t.Origin))
	fmt.Fprintf(&b, "name         = %s\n", tomlString(t.Name))
	fmt.Fprintf(&b, "genesis_hash = %s\n", tomlString(hex.EncodeToString(t.GenesisHash)))
	fmt.Fprintf(&b, "log_key      = %s\n", tomlString(t.LogKey))

	urls := make([]string, 0, len(t.LogURLs))
	for _, u := range t.LogURLs {
		urls = append(urls, tomlString(u))
	}
	fmt.Fprintf(&b, "log_urls     = [%s]\n", strings.Join(urls, ", "))
	fmt.Fprintf(&b, "policy       = %s\n", tomlString(t.Policy))

	if t.Anchor != nil {
		keys := make([]string, 0, len(t.Anchor))
		for key := range t.Anchor {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			switch value := t.Anchor[key].(type) {
			case string:
				parts = append(parts, fmt.Sprintf("%s = %s", key, tomlString(value)))
			default:
				parts = append(parts, fmt.Sprintf("%s = %v", key, value))
			}
		}
		fmt.Fprintf(&b, "anchor       = { %s }\n", strings.Join(parts, ", "))
	}
	for _, w := range t.Witnesses {
		b.WriteString("\n[[witness]]\n")
		fmt.Fprintf(&b, "name = %s\n", tomlString(w.Name))
		fmt.Fprintf(&b, "key  = %s\n", tomlString(w.Key))
		if w.HasURL || w.URL != "" {
			fmt.Fprintf(&b, "url  = %s\n", tomlString(w.URL))
		}
	}
	return b.String(), nil
}

// tomlString quotes a basic TOML string. The escapes are TOML's own set, not
// canonical JSON's (§14.2): the two agree on most of it and not on all of it,
// and conflating them is how a policy with a tab in it stops round-tripping.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
