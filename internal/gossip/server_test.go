package gossip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

func vectors() string { return filepath.Join("..", "..", "testdata", "vectors") }

// served stands up a gossip server over the fixture's log, as a node that had
// verified it would hold it.
func served(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(Handler(filepath.Join(vectors(), "served"), ""))
	t.Cleanup(server.Close)
	return server
}

// The property the whole design rests on: a peer is read by exactly the code
// that reads a log. No gossip-specific verification exists, because a peer
// serves bytes and the receiver checks them the same way -- signature, quorum,
// tiles, tree, replay (GOSSIP part 6).
func TestAPeerVerifiesAsALogDoes(t *testing.T) {
	peer := served(t)

	result, err := logclient.Verify(Peer(peer.URL), anchorOf(t))
	if err != nil {
		t.Fatalf("a peer's gossip endpoint does not verify as a log: %v", err)
	}
	if result.Checkpoint.Size != 90 {
		t.Errorf("size = %d, want the fixture's 90", result.Checkpoint.Size)
	}
	if len(result.Cosignatures) == 0 {
		t.Error("a peer must pass on the cosignatures; a head without them is refused")
	}
}

func TestTheEndpointsAreTheDocumentedOnes(t *testing.T) {
	peer := served(t)

	// The fixture's log is 90 entries, so its tiles are partial -- which is
	// the normal case for a log that is not a multiple of 256 entries, and
	// the path shape a peer actually has to serve.
	for _, path := range []string{
		"/norn/checkpoint",
		"/norn/tile/entries/000.p/90",
		"/norn/tile/0/000.p/90",
	} {
		resp, err := http.Get(peer.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
	}
}

// A peer answers questions; it does not take instructions. Everything a node
// might want to push -- an entry, a claim about a size -- goes to the log,
// which is the only thing that can decide anything.
func TestOnlyReadsAreServed(t *testing.T) {
	peer := served(t)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req, err := http.NewRequest(method, peer.URL+"/norn/checkpoint", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s /norn/checkpoint = %d, want 405", method, resp.StatusCode)
		}
	}
}

// The mirror directory is the whole world this server can see. A node also
// holds `proven.json`, its proof bundles and -- shortly -- its fork evidence,
// and none of that is a peer's business to read off the filesystem.
func TestNothingOutsideTheMirrorIsReachable(t *testing.T) {
	dir := t.TempDir()
	mirror := filepath.Join(dir, "mirror")
	if err := os.MkdirAll(mirror, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirror, "checkpoint"), []byte("head\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A sibling the node keeps for itself.
	if err := os.WriteFile(filepath.Join(dir, "secrets"), []byte("not yours"), 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(Handler(mirror, ""))
	t.Cleanup(server.Close)

	for _, attempt := range []string{
		"/norn/../secrets",
		"/norn/tile/../../secrets",
		"/norn/tile/..%2f..%2fsecrets",
		"/norn/./../secrets",
	} {
		resp, err := http.Get(server.URL + attempt)
		if err != nil {
			t.Fatal(err)
		}
		body := make([]byte, 64)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		if strings.Contains(string(body[:n]), "not yours") {
			t.Errorf("GET %s escaped the mirror", attempt)
		}
	}
}

// A node that has verified nothing yet has nothing to say, and says so.
func TestAnEmptyMirrorIsNotFound(t *testing.T) {
	server := httptest.NewServer(Handler(t.TempDir(), ""))
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/norn/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("an empty mirror answered %d, want 404", resp.StatusCode)
	}
}

// `GOSSIP.md` part 6: "on its WireGuard interface address only (unreachable
// outside the tunnel)". That is a property of where the listener binds, and
// the safest way to have it is to make the address underivable from anything
// but the interface -- so there is no flag to get wrong and no default that
// is 0.0.0.0.
func TestTheListenAddressComesFromTheInterface(t *testing.T) {
	iface := loopback(t)

	addr, err := TunnelAddress(iface, 8099)
	if err != nil {
		t.Fatalf("TunnelAddress(%s): %v", iface, err)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("%q is not host:port: %v", addr, err)
	}
	if port != "8099" {
		t.Errorf("port = %s", port)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("%q is not an address", host)
	}
	if ip.IsUnspecified() {
		t.Errorf("bound to %s, which is every interface -- the one address this "+
			"must never be", host)
	}
	// And it is genuinely one of that interface's addresses.
	if !addressOf(t, iface, ip) {
		t.Errorf("%s is not an address of %s", ip, iface)
	}
}

func TestAnInterfaceThatIsNotThereIsAnError(t *testing.T) {
	if _, err := TunnelAddress("norn-nonexistent0", 8099); err == nil {
		t.Fatal("an address was produced for an interface that does not exist")
	}
}

// --- helpers ---------------------------------------------------------------

func anchorOf(t *testing.T) logclient.Anchor {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return logclient.Anchor{
		Anchor:  replay.Anchor{Net: doc.Net, GenesisHash: doc.GenesisHash},
		LogKeys: []string{doc.LogKey}, Policy: doc.Policy,
	}
}

// loopback is an interface every machine has, standing in for a tunnel.
func loopback(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Name
		}
	}
	t.Skip("no loopback interface to stand in for a tunnel")
	return ""
}

func addressOf(t *testing.T, name string, ip net.IP) bool {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		if network, ok := addr.(*net.IPNet); ok && network.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// `GOSSIP.md` part 6 lists `GET /norn/evidence` — "any fork evidence it
// holds". It is served from a different directory than the mirror on purpose:
// a node's evidence lives beside its `proven.json` and its proof bundles, and
// 4.5b established that none of that is reachable through the mirror. Evidence
// is the one exception, and it is an exception by being named.
func TestEvidenceIsServedWhenThereIsSome(t *testing.T) {
	evidence := t.TempDir()
	if err := os.WriteFile(filepath.Join(evidence, "1760000000.evidence"),
		[]byte("proof bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(Handler(filepath.Join(vectors(), "served"), evidence))
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/norn/evidence")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /norn/evidence = %d", resp.StatusCode)
	}
	body := make([]byte, 64)
	n, _ := resp.Body.Read(body)
	if string(body[:n]) != "proof bytes" {
		t.Errorf("served %q", body[:n])
	}
}

// A node with nothing to report says so, and that is the normal case.
func TestNoEvidenceIsNotFound(t *testing.T) {
	server := httptest.NewServer(Handler(filepath.Join(vectors(), "served"), t.TempDir()))
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/norn/evidence")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("a node holding no evidence answered %d", resp.StatusCode)
	}
}

// Serving evidence must not open the directory it lives in. The rest of that
// directory is a node's own business.
func TestOnlyEvidenceIsReachableFromTheEvidenceDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "1760000000.evidence"),
		[]byte("proof bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not yours"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(Handler(filepath.Join(vectors(), "served"), dir))
	t.Cleanup(server.Close)

	for _, attempt := range []string{"/norn/evidence/notes.txt", "/norn/evidence/"} {
		resp, err := http.Get(server.URL + attempt)
		if err != nil {
			t.Fatal(err)
		}
		body := make([]byte, 64)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		if strings.Contains(string(body[:n]), "not yours") {
			t.Errorf("GET %s reached a file beside the evidence", attempt)
		}
	}
}
