// Package genesis turns a ceremony into the two artefacts a network starts
// from: its first entry, and the trust file every node is provisioned with.
//
// It exists as a package rather than as CLI code because the two artefacts
// must agree — `norn.trust.genesis_hash` is the leaf hash of that exact entry
// (§9.1) — and because a network built wrong is not something you notice
// later. A root set the thresholds cannot satisfy, a log key named for another
// origin, a quorum over witnesses the file never lists: each of those produces
// a network that looks finished and can never accept a checkpoint. So Build
// refuses them here, and then checks its own work by replaying what it made.
//
// Not here: paper roots. Turning a 24-word mnemonic into a seed needs a
// wordlist decision (BIP-39's, or one of Norn's), and inventing that quietly
// would be worse than leaving `ENROLLMENT.md` tier 3 unimplemented and saying so.
package genesis

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

// NetLen is the length of a net_id (§2).
const NetLen = 16

// MaxNameLen is §9.1's cap on the network name.
const MaxNameLen = 64

// Witness is one cosigner the network will require.
type Witness struct {
	// Name is the short label this network files the witness under, and the
	// one its policy evaluates the quorum over.
	Name string
	Key  ed25519.PublicKey
	URL  string
	// NoteName is the name inside the witness's own key, which is what its
	// cosignatures carry. It is usually `norn-witness/<Name>` -- but a witness
	// this network did not create has a name of its own, and signing under
	// anything else produces a line nothing here would match.
	NoteName string
}

// noteName is the name this witness's cosignatures carry.
func (w Witness) noteName() string {
	if w.NoteName != "" {
		return w.NoteName
	}
	return "norn-witness/" + w.Name
}

// Ceremony is a network about to exist.
type Ceremony struct {
	Name string
	// Net is generated when empty, which is the normal case: a network id is
	// 16 random bytes and nobody should have to choose them.
	Net []byte

	Roots     []ed25519.PublicKey
	RootThr   uint64
	Signers   []ed25519.PublicKey
	SignerThr uint64
	Params    map[string]any // optional; §4.5 defaults apply to what is absent

	LogKey    ed25519.PublicKey
	LogURLs   []string
	Witnesses []Witness

	// Policy is used verbatim when set. Otherwise one is generated over the
	// log and the witnesses, with PolicyQuorum cosignatures required
	// (default: all of them).
	Policy       string
	PolicyQuorum uint64

	Anchor map[string]any // optional §9.1 anchor block
	TS     uint64         // genesis timestamp; now when zero
}

// Result is everything a new network needs to exist.
type Result struct {
	Entry       []byte // the signed genesis entry, ready to submit
	Trust       *trust.Trust
	TrustCBOR   []byte
	TrustTOML   string
	Fingerprint string
}

// now is the clock the ceremony stamps genesis with.
func now() time.Time { return time.Now() }

func ceremonyErrorf(format string, args ...any) error {
	return fmt.Errorf("genesis: "+format, args...)
}

// Build makes the genesis entry and the trust file, signing with the roots
// provided. Every signer must be one of the ceremony's roots, and there must be
// at least `root_thr` of them.
func Build(c Ceremony, signers []crypto.Signer) (*Result, error) {
	if err := c.check(); err != nil {
		return nil, err
	}

	net := c.Net
	if len(net) == 0 {
		net = make([]byte, NetLen)
		if _, err := rand.Read(net); err != nil {
			return nil, ceremonyErrorf("%w", err)
		}
	}
	origin, err := trust.OriginFor(net)
	if err != nil {
		return nil, err
	}

	ts := c.TS
	if ts == 0 {
		ts = uint64(now().Unix())
	}
	body := map[string]any{
		"name": c.Name, "roots": toAny(c.Roots), "root_thr": c.RootThr,
		"signers": toAny(c.Signers), "signer_thr": c.SignerThr,
	}
	if len(c.Params) > 0 {
		body["params"] = c.Params
	}
	// No `after`: genesis is entry 0, and a floor under index 0 says nothing.
	env := &entry.Envelope{V: entry.Version, T: "genesis", Net: net, TS: ts, Body: body}

	for _, signer := range signers {
		public, ok := signer.Public().(ed25519.PublicKey)
		if !ok {
			return nil, ceremonyErrorf("a genesis signer must be Ed25519")
		}
		if !contains(c.Roots, public) {
			return nil, ceremonyErrorf("%s is not a root of this ceremony; only roots "+
				"authorise a genesis (§4.3)", entry.Kid(public))
		}
		if err := entry.Sign(env, signer, "root"); err != nil {
			return nil, err
		}
	}
	if uint64(len(env.Sigs)) < c.RootThr {
		return nil, ceremonyErrorf("%d signature(s) but root_thr is %d; the network's own "+
			"first entry would be refused", len(env.Sigs), c.RootThr)
	}

	raw, err := entry.Encode(env)
	if err != nil {
		return nil, err
	}

	policy := c.Policy
	if policy == "" {
		policy = buildPolicy(origin, c.LogKey, c.LogURLs, c.Witnesses, c.quorum())
	}
	witnesses := make([]trust.Witness, 0, len(c.Witnesses))
	for _, w := range c.Witnesses {
		witnesses = append(witnesses, trust.Witness{
			// A witness publishes a cosignature key (algorithm 0x04), not a
			// note key: the log signs checkpoints, a witness cosigns them.
			Name: w.Name, Key: note.CosignerVerifierKey(w.noteName(), w.Key), URL: w.URL,
		})
	}

	anchor := &trust.Trust{
		Version: trust.Version, Net: net, Origin: origin, Name: c.Name,
		GenesisHash: entry.LeafHash(raw),
		// §9.1 binds the log key's note name to the origin, so it is derived
		// here rather than accepted as text: a caller cannot get it wrong.
		LogKey:  note.VerifierKey(origin, c.LogKey),
		LogURLs: c.LogURLs, Witnesses: witnesses, Policy: policy, Anchor: c.Anchor,
	}
	if err := anchor.Validate(); err != nil {
		return nil, ceremonyErrorf("the trust file this ceremony produced is not usable: %w", err)
	}
	encoded, err := anchor.Encode()
	if err != nil {
		return nil, err
	}
	fingerprint, err := anchor.Fingerprint()
	if err != nil {
		return nil, err
	}
	rendered, err := anchor.ToTOML()
	if err != nil {
		return nil, err
	}

	// Check the work: replay the entry under the anchor just built. A ceremony
	// whose output does not replay has created a network nobody can join.
	st := replay.Replay(replay.Anchor{Net: net, GenesisHash: anchor.GenesisHash}, [][]byte{raw})
	if len(st.Rejected) > 0 {
		return nil, ceremonyErrorf("the genesis this ceremony produced does not replay: %s",
			st.Rejected[0].Reason)
	}

	return &Result{Entry: raw, Trust: anchor, TrustCBOR: encoded,
		TrustTOML: rendered, Fingerprint: fingerprint}, nil
}

// quorum is how many cosignatures the generated policy requires.
func (c Ceremony) quorum() uint64 {
	if c.PolicyQuorum > 0 {
		return c.PolicyQuorum
	}
	return uint64(len(c.Witnesses))
}

func (c Ceremony) check() error {
	if n := len(c.Name); n < 1 || n > MaxNameLen {
		return ceremonyErrorf("name must be 1-%d bytes, got %d", MaxNameLen, n)
	}
	if len(c.Net) != 0 && len(c.Net) != NetLen {
		return ceremonyErrorf("net must be %d bytes", NetLen)
	}
	if len(c.Roots) == 0 {
		return ceremonyErrorf("a network needs at least one root")
	}
	if len(c.Signers) == 0 {
		return ceremonyErrorf("a network needs at least one signer, or no device can enrol")
	}
	if c.RootThr < 1 || c.RootThr > uint64(len(c.Roots)) {
		return ceremonyErrorf("root_thr must be 1..%d, got %d", len(c.Roots), c.RootThr)
	}
	if c.SignerThr < 1 || c.SignerThr > uint64(len(c.Signers)) {
		return ceremonyErrorf("signer_thr must be 1..%d, got %d", len(c.Signers), c.SignerThr)
	}
	if err := distinct(c.Roots, "root"); err != nil {
		return err
	}
	if err := distinct(c.Signers, "signer"); err != nil {
		return err
	}
	for _, root := range c.Roots {
		if contains(c.Signers, root) {
			return ceremonyErrorf("%s is both a root and a signer; a key counts for one "+
				"role only (§4.3)", entry.Kid(root))
		}
	}
	if len(c.LogKey) != ed25519.PublicKeySize {
		return ceremonyErrorf("the log key is required, and must be an Ed25519 public key")
	}
	if len(c.LogURLs) == 0 {
		return ceremonyErrorf("at least one log URL is required (§9.1)")
	}
	if len(c.Witnesses) == 0 {
		return ceremonyErrorf("at least one witness is required: with nothing to cosign, " +
			"the policy's quorum can never be met (§9.1)")
	}
	seen := map[string]bool{}
	for _, w := range c.Witnesses {
		if w.Name == "" {
			return ceremonyErrorf("every witness needs a name")
		}
		if seen[w.Name] {
			return ceremonyErrorf("two witnesses share the name %q", w.Name)
		}
		seen[w.Name] = true
		if len(w.Key) != ed25519.PublicKeySize {
			return ceremonyErrorf("witness %s needs an Ed25519 public key", w.Name)
		}
	}
	if c.PolicyQuorum > uint64(len(c.Witnesses)) {
		return ceremonyErrorf("the policy quorum is %d but there are %d witnesses; "+
			"a quorum nobody can reach stops every checkpoint", c.PolicyQuorum, len(c.Witnesses))
	}
	return nil
}

// buildPolicy renders a `c2sp.org/tlog-policy` document over the log and the
// witnesses.
//
// Byte compatibility with the published grammar is **not** claimed: like §8.1's
// proof bundles, this follows the shape the suite has used since Phase 0 and is
// checked against a real witness in Phase 4, not before.
func buildPolicy(origin string, logKey ed25519.PublicKey, urls []string,
	witnesses []Witness, quorum uint64) string {

	var b strings.Builder
	fmt.Fprintf(&b, "log %s %s\n", note.VerifierKey(origin, logKey), urls[0])
	names := make([]string, 0, len(witnesses))
	for _, w := range witnesses {
		fmt.Fprintf(&b, "witness %s %s", w.Name,
			note.CosignerVerifierKey(w.noteName(), w.Key))
		if w.URL != "" {
			fmt.Fprintf(&b, " %s", w.URL)
		}
		b.WriteString("\n")
		names = append(names, w.Name)
	}
	sort.Strings(names)
	fmt.Fprintf(&b, "group all %d %s\n", quorum, strings.Join(names, " "))
	b.WriteString("quorum all\n")
	return b.String()
}

// witnessName is the note name a witness signs under.
func toAny(keys []ed25519.PublicKey) []any {
	out := make([]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, []byte(key))
	}
	return out
}

func contains(set []ed25519.PublicKey, want ed25519.PublicKey) bool {
	for _, key := range set {
		if bytes.Equal(key, want) {
			return true
		}
	}
	return false
}

func distinct(set []ed25519.PublicKey, role string) error {
	for i, key := range set {
		for _, other := range set[i+1:] {
			if bytes.Equal(key, other) {
				return ceremonyErrorf("%s %s is listed twice", role, entry.Kid(key))
			}
		}
	}
	return nil
}
