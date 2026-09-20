// Command norn-log runs a Norn log: it serves the tile directory and accepts
// submissions at `<prefix>/add`.
//
// The read side is files, and nothing here is required to serve them --
// `PLAN.md`'s gate says plain nginx must be able to. This binary exists for the
// one thing a static server cannot do, and for the lab, where running a single
// process is easier than running two.
package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/logserver"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "norn-log:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("norn-log", flag.ContinueOnError)
	dir := fs.String("dir", "", "the log directory to serve and append to (required)")
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	keyPath := fs.String("key", "", "the log's signing key, an OpenSSH private key file (required)")
	trustPath := fs.String("trust", "", "a norn.trust naming this network (required)")
	var selfWitness repeated
	fs.Var(&selfWitness, "self-witness",
		"cosign this log's own checkpoints as `name=keyfile`; repeat for more")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{"-dir": *dir, "-key": *keyPath, "-trust": *trustPath} {
		if value == "" {
			fs.Usage()
			return fmt.Errorf("%s is required", name)
		}
	}

	raw, err := os.ReadFile(*trustPath)
	if err != nil {
		return err
	}
	anchor, err := trust.Parse(raw)
	if err != nil {
		return err
	}
	if err := anchor.Validate(); err != nil {
		return fmt.Errorf("the trust file is not a usable anchor: %w", err)
	}

	key, _, err := keyfile.Read(*keyPath)
	if err != nil {
		return err
	}
	// §9.1 binds the log key's note name to the origin, so a key that does not
	// match this network's trust file would sign checkpoints nobody here can
	// verify. Catch it at startup rather than at the first submission.
	if err := checkKeyMatchesAnchor(key, anchor); err != nil {
		return err
	}

	// A verifier checks the witness quorum (§10 step 3), so a log nothing
	// cosigns publishes heads every correctly-configured node refuses. Holding
	// the witness keys here answers that -- and protects against nothing,
	// because a witness on the log's own host is independent of nothing
	// (GOSSIP part 3). It is the bootstrap and lab configuration; a real
	// deployment pushes to witnesses elsewhere.
	signers, err := selfWitnesses(selfWitness, anchor)
	if err != nil {
		return err
	}
	var opts []tlogstore.Option
	if len(signers) > 0 {
		opts = append(opts, tlogstore.WithCosigner(
			tlogstore.CosignerFunc(cosign.Append(signers, time.Now))))
		for _, s := range signers {
			fmt.Fprintf(os.Stderr, "norn-log: self-witnessing as %s -- this log cosigns "+
				"its own checkpoints, which is independence from nothing (GOSSIP part 3)\n", s.Name)
		}
	}
	store, err := tlogstore.Open(*dir, anchor.Origin, key, opts...)
	if err != nil {
		return err
	}
	server, err := logserver.New(store, *dir, anchor.Origin, key,
		replay.Anchor{Net: anchor.Net, GenesisHash: anchor.GenesisHash})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "norn-log %s\n  dir    %s\n  size   %d\n  listen %s\n",
		anchor.Origin, *dir, store.Size(), *listen)
	fmt.Fprintf(os.Stderr, "  note   rate limiting (§7's 429) is not implemented\n")
	return http.ListenAndServe(*listen, server.Handler())
}

// checkKeyMatchesAnchor refuses a key the network's own trust file does not
// name as its log key.
func checkKeyMatchesAnchor(key interface{ Public() crypto.PublicKey }, anchor *trust.Trust) error {
	verifier, err := note.ParseVerifierKey(anchor.LogKey)
	if err != nil {
		return err
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("the log key must be Ed25519")
	}
	if !bytes.Equal(verifier.Public, public) {
		return fmt.Errorf("this key is not the log key in %s (trust file names %s)",
			anchor.Origin, hex.EncodeToString(verifier.Public[:8]))
	}
	return nil
}

// repeated collects a flag given more than once.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

// selfWitnesses reads the witness keys this log holds itself and checks each
// against the network's own policy. A name the policy never mentions, or the
// right name under the wrong key, would produce cosignatures no node counts --
// a log that looks healthy to its operator and is refused by every verifier.
// That is worth catching at startup rather than at the first submission.
func selfWitnesses(specs []string, anchor *trust.Trust) ([]cosign.Signer, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		return nil, fmt.Errorf("this network's policy does not parse: %w", err)
	}
	named := map[string]string{}
	for _, w := range rules.Witnesses {
		named[w.Name] = w.Key
	}

	var signers []cosign.Signer
	for _, spec := range specs {
		name, path, ok := strings.Cut(spec, "=")
		if !ok || name == "" || path == "" {
			return nil, fmt.Errorf("-self-witness takes name=keyfile, got %q", spec)
		}
		want, listed := named[name]
		if !listed {
			return nil, fmt.Errorf("this network's policy never names a witness called %q", name)
		}
		// The name a cosignature carries is the one inside the witness's key,
		// not the short label the policy files it under -- `witness pi
		// norn-witness/pi+...` is two different names for one party, and
		// signing under the wrong one produces a line nothing matches.
		verifier, err := note.ParseVerifierKey(want)
		if err != nil {
			return nil, fmt.Errorf("witness %s: %w", name, err)
		}
		key, _, err := keyfile.Read(path)
		if err != nil {
			return nil, fmt.Errorf("witness %s: %w", name, err)
		}
		got := note.CosignerVerifierKey(verifier.Name, key.Public().(ed25519.PublicKey))
		if got != want {
			return nil, fmt.Errorf("the key for witness %s is not the one this network's "+
				"policy names, so nothing here would count its cosignatures", name)
		}
		signers = append(signers, cosign.Signer{Name: verifier.Name, Key: key})
	}
	return signers, nil
}
