package peertable

import (
	"errors"
	"fmt"
	"sync"
)

// Fake is an in-memory interface that records what a real one would have been
// told.
//
// It lives beside the code rather than in a test file because the reconciler,
// `nornd` and the lab harness all need it, and because the enforcement
// decisions worth testing are the ones that only occur while an attacker is
// writing to the table at the same time. Reproducing those against a kernel is
// slow and flaky; reproducing them here is a function call.
type Fake struct {
	mu    sync.Mutex
	peers map[Key]Peer

	// Calls records every write in order, so a test can assert *what the
	// interface was told*, not merely what it ended up holding. "Removed the
	// rogue key" and "rewrote the whole table" are different acts with the
	// same final state, and only one of them is watchdog mode.
	Calls []Call

	// FailPeers and FailWrite make the interface behave like one that is down.
	FailPeers error
	FailWrite error
}

// Call is one write, as the interface saw it.
type Call struct {
	Op    string // "replace", "remove" or "update"
	Peers []Peer
	Keys  []Key
}

// NewFake returns an interface holding these peers.
func NewFake(peers ...Peer) *Fake {
	return &Fake{peers: ByKey(peers)}
}

// Peers implements Device.
func (f *Fake) Peers() ([]Peer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailPeers != nil {
		return nil, f.FailPeers
	}
	out := make([]Peer, 0, len(f.peers))
	for _, peer := range f.peers {
		out = append(out, peer)
	}
	return Sorted(out), nil
}

// Replace implements Device.
func (f *Fake) Replace(peers []Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailWrite != nil {
		return f.FailWrite
	}
	f.peers = ByKey(peers)
	f.Calls = append(f.Calls, Call{Op: "replace", Peers: Sorted(peers)})
	return nil
}

// Remove implements Device.
func (f *Fake) Remove(keys []Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailWrite != nil {
		return f.FailWrite
	}
	for _, key := range keys {
		delete(f.peers, key)
	}
	f.Calls = append(f.Calls, Call{Op: "remove", Keys: append([]Key(nil), keys...)})
	return nil
}

// UpdateEndpoints implements Device, and refuses to add a key that is absent
// — that is what UpdateOnly means, and a fake that quietly added one would let
// a bug through that a kernel would have caught.
func (f *Fake) UpdateEndpoints(peers []Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailWrite != nil {
		return f.FailWrite
	}
	for _, peer := range peers {
		if _, present := f.peers[peer.Key]; !present {
			return fmt.Errorf("peertable: UpdateEndpoints would add %s, which is not "+
				"what UpdateOnly does", peer.Key.Short())
		}
	}
	for _, peer := range peers {
		f.peers[peer.Key] = peer
	}
	f.Calls = append(f.Calls, Call{Op: "update", Peers: Sorted(peers)})
	return nil
}

// Writes counts the writes so far, for tests whose subject is "did it touch
// the interface at all" -- observe mode's entire contract.
func (f *Fake) Writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Calls)
}

// Inject adds a peer the way an external writer would: behind Norn's back,
// without going through a call Norn made.
func (f *Fake) Inject(peers ...Peer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, peer := range peers {
		f.peers[peer.Key] = peer
	}
}

// ErrDown is what a fake interface returns when told to be unavailable.
var ErrDown = errors.New("peertable: the interface is unavailable")

var _ Device = (*Fake)(nil)
