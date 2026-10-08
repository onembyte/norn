package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/endpoint"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/reconcile"
)

// routedNode is an owner-mode node over a state directory whose operator has
// written tunnel routes for two proven devices, so its peers have gossip
// addresses.
func routedNode(t *testing.T, logDir, stateDir string, rec *recorder) *Agent {
	t.Helper()
	a, err := New(Config{
		Anchor: anchor(t), Fetcher: logclient.Dir(logDir), Device: peertable.NewFake(),
		Mode: reconcile.Owner, RunDir: t.TempDir(), StateDir: stateDir, Emit: rec.emit,
		Provider: endpoint.Static{Peers: map[string]endpoint.Hints{
			"nas":    {AllowedIPs: prefixes(t, "10.9.0.2/32")},
			"pi-cam": {AllowedIPs: prefixes(t, "10.9.0.3/32")},
		}},
		Now:  func() time.Time { return time.Unix(fixtureCosignedAt, 0) },
		Mono: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// D-071 (b). Gossip exists for the node whose log is down, and a reboot while
// the log is down is the ordinary way to arrive in that state. But the peer
// list was read from the head verified in this process, so a rebooted node
// had nobody to ask until the very log it could not reach had answered. The
// head it restored proves the same peers it proved yesterday.
func TestARebootedNodeCanStillNameThePeersItsHeldHeadProves(t *testing.T) {
	dir := advisoryLog(t)
	stateDir := t.TempDir()
	if err := routedNode(t, dir, stateDir, &recorder{}).Once(); err != nil {
		t.Fatal(err)
	}

	// The log is unreachable from the moment the node comes back.
	rec := &recorder{}
	rebooted := routedNode(t, t.TempDir(), stateDir, rec)
	if err := rebooted.Once(); err == nil {
		t.Fatal("an unreachable log verified")
	}
	addresses := rebooted.PeerAddresses(8100)
	if len(addresses) != 2 {
		t.Fatalf("addresses = %v after a reboot with the log down, want the two routed "+
			"proven devices the held head proves", addresses)
	}
	for _, addr := range addresses {
		if !strings.HasPrefix(addr, "http://10.9.0.") {
			t.Errorf("%s is not a tunnel address the log put in a proven peer's allowed-ips", addr)
		}
	}
	// And the held head is still only held: nothing verified here, so nothing
	// was installed (D-069).
	if rec.kinds()[NoStateYet] == 0 {
		t.Errorf("the node did not say that nothing has verified yet: %v", rec.kinds())
	}
}

// Before anything has verified and with nothing restored -- a first start with
// the log down -- there is no head, proven or held, and so no peer to name.
func TestWithNoHeadAtAllThereAreNoPeersToName(t *testing.T) {
	a := routedNode(t, t.TempDir(), t.TempDir(), &recorder{})
	_ = a.Once()
	if got := a.PeerAddresses(8100); len(got) != 0 {
		t.Errorf("addresses = %v with no head at all", got)
	}
}
