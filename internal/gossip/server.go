package gossip

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Prefix is where a node's gossip endpoints live (`GOSSIP.md` part 6).
const Prefix = "/norn/"

// Handler serves this node's mirror to its peers: the checkpoint it has
// adopted and every tile behind it.
//
// It serves **bytes, not claims**. There is no "my size is N" endpoint whose
// word a peer would have to take, and no verification here at all -- the
// receiver runs `logclient.Verify` over what it fetched, exactly as it would
// against the log. That is what makes a lying peer no more dangerous than a
// lying log, and it is why this file is thirty lines rather than a protocol.
//
// `mirror` is the log this node holds, and the entire world the tile endpoints
// can see: a node's `proven.json` and its proof bundles are siblings of it, and
// none of that is a peer's business to read off the filesystem.
//
// `evidence` is the one deliberate exception (`GOSSIP.md` part 6's
// `GET /norn/evidence`), and it is an exception by being **named**: a single
// file is served from it, not the directory. Empty means this node has nothing
// to say, which is the normal case.
func Handler(mirror, evidence string) http.Handler {
	files := http.FileServer(http.Dir(mirror))
	mux := http.NewServeMux()
	mux.Handle(Prefix, http.StripPrefix(Prefix, readOnly(noListing(files))))
	mux.Handle(EvidencePath, readOnly(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			serveEvidence(w, r, evidence)
		})))
	return mux
}

// EvidencePath is where a node publishes a fork it has proved.
const EvidencePath = Prefix + "evidence"

// serveEvidence hands over the newest evidence file, and only that.
//
// Newest because a node freezes on the first fork it proves, so a second file
// means the operator reset with a new trust file and forked again -- and the
// later one is the one about the network now running. A node with nothing to
// report answers 404, which is what almost every node answers almost always.
func serveEvidence(w http.ResponseWriter, r *http.Request, dir string) {
	if dir == "" {
		http.NotFound(w, r)
		return
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.evidence"))
	if err != nil || len(matches) == 0 {
		http.NotFound(w, r)
		return
	}
	sort.Strings(matches) // the names are unix seconds, so this is chronological
	raw, err := os.ReadFile(matches[len(matches)-1])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	_, _ = w.Write(raw)
}

// readOnly refuses anything but a read. A peer answers questions; it does not
// take instructions. Everything a node might push -- an entry, a claim about a
// size -- goes to the log, which is the only thing that can decide anything.
func readOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "a peer serves data and takes no instructions",
				http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// noListing hides directory indexes: a peer fetches paths `tlog-tiles` names,
// and does not need to be told what else is here.
func noListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Peer reads a peer's gossip endpoints as a log.
//
// It is a `logclient.Fetcher`, which is the entire integration: gossip adds a
// source, not a trust model.
type Peer string

// Fetch implements logclient.Fetcher.
func (p Peer) Fetch(path string) ([]byte, error) {
	base := strings.TrimSuffix(string(p), "/")
	resp, err := http.Get(base + Prefix + strings.TrimPrefix(path, "/"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer %s answered %d for %s", base, resp.StatusCode, path)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxFetch))
}

// TunnelAddress is where a node's gossip server binds: an address of the
// WireGuard interface itself, and nothing else.
//
// `GOSSIP.md` part 6 says "on its WireGuard interface address only
// (unreachable outside the tunnel)", and the safest way to have that property
// is to leave no way to express anything else. There is deliberately no flag
// for a listen address, so there is none to get wrong and no default that is
// `0.0.0.0` -- an operator cannot expose a node's mirror to the internet by
// typing the wrong thing, because there is nothing to type.
func TunnelAddress(iface string, port int) (string, error) {
	device, err := net.InterfaceByName(iface)
	if err != nil {
		return "", fmt.Errorf("gossip: %s: %w", iface, err)
	}
	addrs, err := device.Addrs()
	if err != nil {
		return "", fmt.Errorf("gossip: %s: %w", iface, err)
	}
	for _, addr := range addrs {
		network, ok := addr.(*net.IPNet)
		if !ok || network.IP.IsUnspecified() {
			continue
		}
		return net.JoinHostPort(network.IP.String(), strconv.Itoa(port)), nil
	}
	return "", fmt.Errorf("gossip: %s has no address to serve on; a node gossips on "+
		"the tunnel or not at all", iface)
}

// maxFetch bounds what one peer can make this node hold for a single file.
// An entry bundle is 256 entries of at most 64 KiB, and a tile is smaller.
const maxFetch = 24 << 20
