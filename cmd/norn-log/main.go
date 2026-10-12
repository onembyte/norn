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
	"errors"
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
	"github.com/onembyte/norn/internal/witness"
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
	interval := fs.Duration("checkpoint-interval", DefaultCheckpointInterval,
		"how often an idle log republishes, to refresh its witnesses' cosignatures")
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
	// The trust file already says where this network's witnesses live, so a
	// log does not need to be told twice -- and a witness the policy does not
	// name is one nothing would count anyway.
	remote := witnessClients(anchor)
	proofs := &storeProofs{}
	// Both kinds of cosigner reach the checkpoint. A log bootstrapping with a
	// local key while its remote witnesses come up is a real state, and
	// setting the option twice would silently drop one of them.
	var cosigners []tlogstore.Cosigner
	if len(remote) > 0 {
		cosigners = append(cosigners, witness.NewSubmitter(remote, proofs, func(err error) {
			if errors.Is(err, errNotOpenYet) {
				return
			}
			fmt.Fprintln(os.Stderr, "norn-log:", err)
		}))
		for _, client := range remote {
			fmt.Fprintf(os.Stderr, "norn-log: witness %s at %s\n", client.Name, client.URL)
		}
	}
	if len(signers) > 0 {
		cosigners = append(cosigners,
			tlogstore.CosignerFunc(cosign.Append(signers, time.Now)))
		for _, s := range signers {
			fmt.Fprintf(os.Stderr, "norn-log: self-witnessing as %s -- this log cosigns "+
				"its own checkpoints, which is independence from nothing (GOSSIP part 3)\n", s.Name)
		}
	}
	var opts []tlogstore.Option
	if len(cosigners) > 0 {
		opts = append(opts, tlogstore.WithCosigner(tlogstore.Cosigners(cosigners...)))
	}
	store, err := tlogstore.Open(*dir, anchor.Origin, key, opts...)
	if err != nil {
		return err
	}
	proofs.store = store
	server, err := logserver.New(store, *dir, anchor.Origin, key,
		replay.FromTrust(anchor))
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "norn-log %s\n  dir    %s\n  size   %d\n  listen %s\n",
		anchor.Origin, *dir, store.Size(), *listen)
	fmt.Fprintf(os.Stderr, "  rate   %g submissions/s per remote host, burst %d (SPEC §7)\n",
		logserver.DefaultRate, logserver.DefaultBurst)

	// Refreshing happens in the background, starting at once.
	//
	// At once, because the head this store opened with was written before the
	// witness client had a tree to build proofs from. In the background,
	// because a log must not wait on a third party to start serving: with
	// witnesses that are down, a synchronous first round would hold the
	// listener closed for the whole timeout -- turning a witness outage into a
	// log outage at exactly the moment an operator is trying to bring the log
	// back (GOSSIP T6).
	if len(remote) > 0 && *interval > 0 {
		go refresh(store, *interval)
	}
	return newServer(*listen, server.Handler()).ListenAndServe()
}

// The listener's limits (SEC-034). The log is the server every node and the
// monitor read from, and it was served with http.ListenAndServe -- no header,
// read, write or idle timeout and Go's 1 MB header cap -- so a client that
// sent half a request line and then nothing held a connection, a goroutine
// and a file descriptor for as long as it liked. Generous against honest use:
// a request header is a few hundred bytes, a submission is one entry
// (cbor.MaxEntryBytes, read under its own cap), and the largest response is
// one tile or bundle. Variables so a test can shorten them.
var (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = time.Minute
	idleTimeout       = 2 * time.Minute
)

// maxHeaderBytes caps a request's header block well under Go's 1 MB default;
// nothing a reader or submitter sends needs more than a few hundred bytes.
const maxHeaderBytes = 16 << 10

// newServer is the log's HTTP server with every limit set.
func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
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

// witnessClients builds a client per witness the trust file gives an address
// for. A witness with no `url` is one this node cannot reach -- it may still
// count towards the quorum when somebody else collects its cosignature, so it
// is skipped rather than refused.
func witnessClients(anchor *trust.Trust) []*witness.Client {
	var out []*witness.Client
	for _, w := range anchor.Witnesses {
		if w.URL == "" {
			continue
		}
		out = append(out, &witness.Client{Name: w.Name, URL: w.URL, Key: w.Key})
	}
	return out
}

// storeProofs supplies consistency proofs from the log's own tree.
//
// The store is filled in after it is opened, because the store is built *with*
// the submitter that needs these proofs. Tying the two together afterwards is
// the smaller knot: the alternative is a store that knows how to talk to
// witnesses, which is the dependency `internal/witness` exists to avoid.
type storeProofs struct{ store *tlogstore.Store }

// errNotOpenYet marks the one refusal that is expected on every start.
var errNotOpenYet = errors.New("the log is not open yet")

func (p *storeProofs) ConsistencyProof(old int64) ([][]byte, error) {
	if p.store == nil {
		// The store republishes as it opens, before this is wired -- so the
		// very first round has nothing to prove from. It is not a failure and
		// it is not worth a line on an operator's console: the background
		// refresh asks again a moment later with the tree in hand.
		return nil, errNotOpenYet
	}
	if old == 0 {
		return nil, nil // "The proof MUST be empty if the old size is zero."
	}
	proof, err := p.store.ConsistencyProof(old)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(proof))
	for _, hash := range proof {
		out = append(out, append([]byte(nil), hash[:]...))
	}
	return out, nil
}

// DefaultCheckpointInterval is SPEC §4.5's `checkpoint_interval` default: the
// most time a log promises to leave between checkpoints.
const DefaultCheckpointInterval = 60 * time.Second

// refresh republishes the head on a tick, so an idle log's cosignatures stay
// current. A failure is reported and the loop continues: the submitter already
// treats an unreachable witness as survivable, and a log that stopped
// refreshing because one tick failed would be the outage it is avoiding.
func refresh(store *tlogstore.Store, every time.Duration) {
	for {
		if err := store.Republish(); err != nil {
			fmt.Fprintln(os.Stderr, "norn-log: refreshing the checkpoint:", err)
		}
		time.Sleep(every)
	}
}
