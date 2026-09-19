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

	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/logserver"
	"github.com/onembyte/norn/internal/note"
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

	store, err := tlogstore.Open(*dir, anchor.Origin, key)
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
