package main

import (
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/genesis"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/sshagent"
)

func initCmd(args []string) error {
	fs := newFlagSet("init")
	name := fs.String("name", "", "a human label for the network (required)")
	out := fs.String("out", ".", "directory to write genesis.cbor and norn.trust into")
	rootThr := fs.Uint64("root-thr", 0, "roots required to sign governance (default: a majority)")
	signerThr := fs.Uint64("signer-thr", 1, "signers required to enrol a device")
	quorum := fs.Uint64("quorum", 0, "witness cosignatures the policy requires (default: all)")
	logKeyPath := fs.String("log-key", "", "the log's signing key file; created if absent (required)")

	var roots, rootPubs, rootAgents, signers, signerPubs, logURLs, witnesses repeated
	fs.Var(&roots, "root", "a root key `file`; created if absent. Repeat for more roots")
	fs.Var(&rootPubs, "root-pub", "a root's public key as 64 `hex` digits, for a key held elsewhere")
	fs.Var(&rootAgents, "root-agent", "a root held in the ssh-agent, by `kid`")
	fs.Var(&signers, "signer", "a signer key `file`; created if absent")
	fs.Var(&signerPubs, "signer-pub", "a signer's public key as 64 `hex` digits")
	fs.Var(&logURLs, "log-url", "where the log will be served; repeat for more")
	fs.Var(&witnesses, "witness", "a witness as `name=hex` or name=keyfile; repeat for more")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *logKeyPath == "" || len(logURLs) == 0 {
		fs.Usage()
		return errors.New("-name, -log-key and at least one -log-url are required")
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	created := []string{}

	// Roots. A key file both joins the set and signs; a bare public key joins
	// the set without signing, which is how a paper or hardware root that is
	// not present at this moment still becomes part of the network.
	var rootKeys []ed25519.PublicKey
	var ceremonySigners []crypto.Signer
	for _, path := range roots {
		key, made, err := keyAt(path)
		if err != nil {
			return err
		}
		if made {
			created = append(created, path)
		}
		rootKeys = append(rootKeys, key.Public().(ed25519.PublicKey))
		ceremonySigners = append(ceremonySigners, key)
	}
	for _, text := range rootPubs {
		key, err := publicFromHex(text)
		if err != nil {
			return fmt.Errorf("-root-pub: %w", err)
		}
		rootKeys = append(rootKeys, key)
	}
	for _, kid := range rootAgents {
		signer, public, err := agentSigner(kid)
		if err != nil {
			return err
		}
		rootKeys = append(rootKeys, public)
		ceremonySigners = append(ceremonySigners, signer)
	}

	var signerKeys []ed25519.PublicKey
	for _, path := range signers {
		key, made, err := keyAt(path)
		if err != nil {
			return err
		}
		if made {
			created = append(created, path)
		}
		signerKeys = append(signerKeys, key.Public().(ed25519.PublicKey))
	}
	for _, text := range signerPubs {
		key, err := publicFromHex(text)
		if err != nil {
			return fmt.Errorf("-signer-pub: %w", err)
		}
		signerKeys = append(signerKeys, key)
	}

	logKey, made, err := keyAt(*logKeyPath)
	if err != nil {
		return err
	}
	if made {
		created = append(created, *logKeyPath)
	}

	var witnessSet []genesis.Witness
	for _, spec := range witnesses {
		name, value, found := strings.Cut(spec, "=")
		if !found || name == "" {
			return fmt.Errorf("-witness takes name=hex or name=keyfile, got %q", spec)
		}
		public, err := publicFromHex(value)
		if err != nil {
			key, made, keyErr := keyAt(value)
			if keyErr != nil {
				return fmt.Errorf("witness %s: %v, and %v", name, err, keyErr)
			}
			if made {
				created = append(created, value)
			}
			public = key.Public().(ed25519.PublicKey)
		}
		witnessSet = append(witnessSet, genesis.Witness{Name: name, Key: public})
	}

	threshold := *rootThr
	if threshold == 0 {
		threshold = uint64(len(rootKeys))/2 + 1 // a majority, and it is printed
	}

	result, err := genesis.Build(genesis.Ceremony{
		Name: *name, Roots: rootKeys, RootThr: threshold,
		Signers: signerKeys, SignerThr: *signerThr,
		LogKey: logKey.Public().(ed25519.PublicKey), LogURLs: logURLs,
		Witnesses: witnessSet, PolicyQuorum: *quorum,
	}, ceremonySigners)
	if err != nil {
		return err
	}

	files := map[string][]byte{
		"genesis.cbor":    result.Entry,
		"norn.trust":      result.TrustCBOR,
		"norn.trust.toml": []byte(result.TrustTOML),
	}
	for base, content := range files {
		path := filepath.Join(*out, base)
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; initialising a network over an existing "+
				"one would strand every node holding the old trust file", path)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			return err
		}
	}

	printCeremony(result, *out, threshold, *signerThr, created)
	return nil
}

func printCeremony(result *genesis.Result, out string, rootThr, signerThr uint64, created []string) {
	w := os.Stderr
	fmt.Fprintf(w, "Network %s created.\n", result.Trust.Name)
	fmt.Fprintf(w, "  origin      %s\n", result.Trust.Origin)
	fmt.Fprintf(w, "  net         %s\n", hex.EncodeToString(result.Trust.Net))
	fmt.Fprintf(w, "  roots       %d, %d required\n", countRoots(result), rootThr)
	fmt.Fprintf(w, "  signers     %d, %d required\n", countSigners(result), signerThr)
	fmt.Fprintf(w, "  witnesses   %d\n", len(result.Trust.Witnesses))
	fmt.Fprintf(w, "  genesis     %s\n", filepath.Join(out, "genesis.cbor"))
	fmt.Fprintf(w, "  trust file  %s\n", filepath.Join(out, "norn.trust"))
	for _, path := range created {
		fmt.Fprintf(w, "  created     %s\n", path)
	}

	fmt.Fprintf(w, "\n  FINGERPRINT  %s\n", result.Fingerprint)
	fmt.Fprintf(w, "\nEvery node is provisioned with norn.trust out of band, and compares that\n"+
		"fingerprint against this screen before trusting it (§9.3). Nothing else in\n"+
		"Norn is taken on faith, so this is the one comparison that matters.\n")
	fmt.Fprintf(w, "\nNext: start `norn-log` on an empty directory with this trust file and\n"+
		"`norn submit` the genesis entry — a network's first entry is entry 0.\n")
}

func countRoots(r *genesis.Result) int {
	env, err := entry.Decode(r.Entry)
	if err != nil {
		return 0
	}
	roots, _ := env.Body["roots"].([]any)
	return len(roots)
}

func countSigners(r *genesis.Result) int {
	env, err := entry.Decode(r.Entry)
	if err != nil {
		return 0
	}
	signers, _ := env.Body["signers"].([]any)
	return len(signers)
}

// keyAt loads a key file, creating one when it is not there. `norn enroll`
// behaves the same way with a device key, and the summary says which files were
// created so a mistyped path is visible rather than silent.
func keyAt(path string) (ed25519.PrivateKey, bool, error) {
	if _, err := os.Stat(path); err == nil {
		key, _, err := keyfile.Read(path)
		return key, false, err
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, false, err
		}
	}
	_, key, err := keyfile.Generate()
	if err != nil {
		return nil, false, err
	}
	if err := keyfile.Write(path, key, "norn "+filepath.Base(path)); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

func publicFromHex(text string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("a public key is %d hex digits, got %d",
			ed25519.PublicKeySize*2, len(text))
	}
	return ed25519.PublicKey(raw), nil
}

func agentSigner(kid string) (crypto.Signer, ed25519.PublicKey, error) {
	client, err := sshagent.Open()
	if err != nil {
		return nil, nil, err
	}
	keys, err := client.Keys()
	if err != nil {
		return nil, nil, err
	}
	for _, key := range keys {
		if entry.Kid(key.Public) == kid {
			signer, err := client.Signer(key.Public)
			return signer, key.Public, err
		}
	}
	return nil, nil, fmt.Errorf("the agent holds no key with kid %s", kid)
}

// repeated collects a flag given more than once.
type repeated []string

func (r *repeated) String() string { return strings.Join(*r, ",") }

func (r *repeated) Set(value string) error {
	if value == "" {
		return errors.New("empty value")
	}
	*r = append(*r, value)
	return nil
}
