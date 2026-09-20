package witness

import (
	"errors"
	"strings"
	"sync"

	"github.com/onembyte/norn/internal/note"
)

// Proofs supplies the consistency proof a witness needs to accept a new head:
// from the size it last cosigned, to the size being submitted.
//
// It is an interface because a log's tree is the log's business. This package
// knows that a proof is a list of hashes and where it goes in the request; it
// does not know how the tree is stored.
type Proofs interface {
	ConsistencyProof(old int64) ([][]byte, error)
}

// Submitter asks a network's witnesses to cosign each checkpoint, and returns
// the head with whatever they returned appended.
//
// **An unreachable witness never stops the log.** `GOSSIP.md`'s T6 is explicit
// about what a witness outage looks like: "2 of 3 witnesses down -> log cannot
// reach quorum; nodes hold last good; degraded after S; recovers when
// witnesses return". The log keeps publishing and the *nodes* decide what an
// under-witnessed head is worth. A log that refused to write instead would
// turn a witness outage into a log outage, and take the network down to
// protect it from being slightly less corroborated.
//
// That is a deliberate change from the rule this project set in 4.1c, which
// failed the publish when cosigning failed. That rule was right for a cosigner
// holding local keys, where a failure is a bug; it is wrong for a network call,
// where a failure is Tuesday.
type Submitter struct {
	clients []*Client
	proofs  Proofs
	// report receives every refusal. A log quietly failing to collect
	// cosignatures looks exactly like a healthy log right up until the nodes
	// start degrading, so nothing here is swallowed.
	report func(error)

	mu sync.Mutex
	// sizes is the tree size each witness last told us it had cosigned. A
	// witness missing here has never answered, and is approached from zero --
	// its 409 is how the log discovers where it actually is, which is why no
	// separate "what size are you at" request exists.
	sizes map[string]int64
}

// NewSubmitter builds a submitter over a network's witnesses.
func NewSubmitter(clients []*Client, proofs Proofs, report func(error)) *Submitter {
	if report == nil {
		report = func(error) {}
	}
	return &Submitter{clients: clients, proofs: proofs, report: report,
		sizes: map[string]int64{}}
}

// Cosign implements the seam a log publishes through: it returns the signed
// checkpoint with every cosignature the witnesses returned appended.
func (s *Submitter) Cosign(signed string) (string, error) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		gathered []string
	)
	for _, client := range s.clients {
		wg.Add(1)
		go func(client *Client) {
			defer wg.Done()
			lines, err := s.ask(client, signed)
			if err != nil {
				s.report(err)
				return
			}
			mu.Lock()
			gathered = append(gathered, lines...)
			mu.Unlock()
		}(client)
	}
	wg.Wait()

	// In the order the network lists its witnesses, so a checkpoint does not
	// change shape because two witnesses answered in a different order.
	out := signed
	for _, client := range s.clients {
		for _, line := range gathered {
			if lineIsFrom(line, client) {
				out += line + "\n"
			}
		}
	}
	return out, nil
}

// ask submits to one witness, correcting once if it says we started in the
// wrong place.
//
// Exactly once: a witness that keeps conflicting is left for the next
// checkpoint rather than retried in a loop. Whatever is wrong -- a witness
// being rebuilt, two logs sharing an origin -- will not be fixed by asking
// again immediately, and a log that spun here would stop publishing.
func (s *Submitter) ask(client *Client, signed string) ([]string, error) {
	lines, err := s.attempt(client, signed, s.sizeFor(client))

	var conflict *ConflictError
	if errors.As(err, &conflict) {
		s.remember(client, conflict.WitnessSize)
		return s.attempt(client, signed, conflict.WitnessSize)
	}
	return lines, err
}

// attempt is one submission from a given size.
func (s *Submitter) attempt(client *Client, signed string, from int64) ([]string, error) {
	proof, err := s.proofs.ConsistencyProof(from)
	if err != nil {
		return nil, witnessErrorf("building the consistency proof from size %d for %s: %v",
			from, client.name(), err)
	}
	lines, err := client.Add(signed, from, proof)
	if err != nil {
		return nil, err
	}
	// It accepted this head, so this is where the next submission starts.
	if size, err := checkpointSize(signed); err == nil {
		s.remember(client, size)
	}
	return lines, nil
}

func (s *Submitter) sizeFor(client *Client) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sizes[client.Name]
}

func (s *Submitter) remember(client *Client, size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sizes[client.Name] = size
}

// lineIsFrom reports whether a signature line carries one of a witness's names.
func lineIsFrom(line string, client *Client) bool {
	for _, key := range append([]string{client.Key}, client.AlsoTrust...) {
		verifier, err := note.ParseVerifierKey(key)
		if err != nil {
			continue
		}
		if strings.HasPrefix(line, note.SigPrefix+verifier.Name+" ") {
			return true
		}
	}
	return false
}
