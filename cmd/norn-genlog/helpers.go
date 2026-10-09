// These helpers support fork, detect, checkpoints-bad, proofs, proofs-bad
// and the served vector directories.

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/cbor"
	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

// logKey is the key the shipped `trust.cbor` names as this network's log key.
//
// It is read from `keys.json` rather than invented here, and that is the whole
// point: the suite has two provenances (§12), and until 2.9g the Go half signed
// its checkpoints with a seed of its own while the reference half's trust file
// named a different key. Nothing noticed, because no verifier checked a
// checkpoint signature until 2.9e-i. A suite whose two halves disagree is a
// suite that cannot be followed.
// seedKey reads one test key out of keys.json.
func seedKey(root, name string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(root, "keys.json"))
	if err != nil {
		return nil, err
	}
	var keys struct {
		Ed25519 map[string]struct {
			Seed string `json:"seed"`
		} `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(keys.Ed25519[name].Seed)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("keys.json has no usable %s seed", name)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// WitnessNames are the fixture's witnesses, in the order the policy lists them.
var WitnessNames = []string{"pi", "vps", "friend"}

// CosignSpread is how much later each witness answers than the one before it.
// Until cold gate run 6 all three cosigned at the same instant, so the newest
// timestamp, the median and the k-th newest agreed and no vector said which
// §5.3 means. They answer seven seconds apart now, which makes the 2-of-3
// quorum time the *second* newest and tells the three readings apart.
const CosignSpread = 7

// CosignedAt is the fixed instant the fixture's witnesses cosign at.
//
// Fixed, because a vector whose bytes changed with the clock could not be
// compared to anything. Witness time is the clock elsewhere (GOSSIP.md part
// 5); here it is a number the suite agrees on.
const CosignedAt = 1_760_003_600

// witnessSigners loads the fixture's witnesses in the order the policy lists
// them, so the cosignature lines land in a fixed order and the fixture stays
// byte-reproducible.
// staggeredCosigner appends each witness's line at its own instant, in policy
// order, by chaining one single-signer `Append` per witness.
func staggeredCosigner(signers []cosignpkg.Signer) func(string) (string, error) {
	return func(signed string) (string, error) {
		out := signed
		for i, s := range signers {
			at := time.Unix(CosignedAt+int64(i*CosignSpread), 0)
			next, err := cosignpkg.Append([]cosignpkg.Signer{s}, cosignpkg.At(at))(out)
			if err != nil {
				return "", err
			}
			out = next
		}
		return out, nil
	}
}

func witnessSigners(root string) ([]cosignpkg.Signer, error) {
	signers := make([]cosignpkg.Signer, 0, len(WitnessNames))
	for _, name := range WitnessNames {
		key, err := seedKey(root, "witness-"+name)
		if err != nil {
			return nil, err
		}
		signers = append(signers, cosignpkg.Signer{Name: "norn-witness/" + name, Key: key})
	}
	return signers, nil
}

// checkCodes refuses to write a manifest whose cases and codes disagree:
// every case names a code on its closed list -- §10.1's for a verifier,
// §11.1's for an evidence reader (D-061) -- and no code names a case that is
// not there. A negative without a code can only say "refused", which a reader
// that runs its checks in the wrong order also says.
func checkCodes[C ~string](dir string, names []string, codes map[string]C, known func(C) bool) error {
	for _, name := range names {
		if code, ok := codes[name]; !ok || !known(code) {
			return fmt.Errorf("%s: case %q names no code on its closed list; every "+
				"negative must say which step refuses it", dir, name)
		}
	}
	if len(codes) != len(names) {
		return fmt.Errorf("%s: %d codes for %d cases", dir, len(codes), len(names))
	}
	return nil
}

// namesOf lists each case's `name`, in order, so a manifest's codes are
// checked against its own cases rather than against a second list of them.
func namesOf[V any](cases []map[string]V) []string {
	out := make([]string, 0, len(cases))
	for _, c := range cases {
		out = append(out, fmt.Sprint(c["name"]))
	}
	return out
}

// withExtraKey re-encodes a CBOR map with one more key, so a closed-schema
// negative differs from a valid artifact in exactly that.
func withExtraKey(raw []byte, key, value string) []byte {
	m := mustMap(raw)
	m[key] = value
	out, err := cbor.Encode(m)
	if err != nil {
		panic(err)
	}
	return out
}

// withVersion re-encodes a CBOR map under another version number.
func withVersion(raw []byte, v uint64) []byte {
	m := mustMap(raw)
	for _, key := range []string{"v", "version"} {
		if _, ok := m[key]; ok {
			m[key] = v
		}
	}
	out, err := cbor.Encode(m)
	if err != nil {
		panic(err)
	}
	return out
}

func mustMap(raw []byte) map[string]any {
	value, err := cbor.Decode(raw)
	if err != nil {
		panic(err)
	}
	m, ok := value.(map[string]any)
	if !ok {
		panic("not a CBOR map")
	}
	return m
}

// mustBody is the note text a signature covers, without the signature lines.
func mustBody(signed string) string {
	i := strings.Index(signed, "\n\n")
	if i < 0 {
		return signed
	}
	return signed[:i+1]
}

// signedHeadOver builds a cosigned checkpoint over exactly these entries.
func signedHeadOver(root, origin string, key ed25519.PrivateKey,
	entries [][]byte, signers []cosignpkg.Signer) (string, error) {

	dir, err := os.MkdirTemp("", "norn-branch")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	store, err := tlogstore.Open(dir, origin, key, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(staggeredCosigner(signers))))
	if err != nil {
		return "", err
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			return "", err
		}
	}
	return store.SignedCheckpoint()
}

// forkEntry is the entry only the second branch carries: a revoke the real
// network never issued, signed by the fixture's own signers so that every
// signature on the forked branch checks out. That is the difficulty a fork
// presents -- nothing about either head looks wrong on its own.
func forkEntry(root string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		return nil, err
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		return nil, err
	}
	env := &entry.Envelope{
		V: entry.Version, T: "revoke", Net: doc.Net, TS: CosignedAt - 100,
		Body: map[string]any{"device_id": "nas", "reason": "the fork's own idea"},
	}
	for _, name := range []string{"signer1", "signer2"} {
		key, err := seedKey(root, name)
		if err != nil {
			return nil, err
		}
		if err := entry.Sign(env, key, "signer"); err != nil {
			return nil, err
		}
	}
	return entry.Encode(env)
}

// forkAt is where the fixture's second branch diverges: far enough in that the
// two share real history, early enough that the divergence is obvious.
const forkAt = 40

// noteBody is the checkpoint text a signature covers: origin, size, root, and
// the newline that ends the last of them.
func noteBody(signed string) (string, error) {
	i := strings.Index(signed, "\n\n")
	if i < 0 {
		return "", fmt.Errorf("checkpoint has no blank line before its signatures")
	}
	return signed[:i+1], nil
}
