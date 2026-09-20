package witness

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
)

// A log asks its witnesses on every checkpoint. `GOSSIP.md`'s T6 settles what
// happens when they do not answer: "2 of 3 witnesses down -> log cannot reach
// quorum; nodes hold last good; degraded after S; recovers when witnesses
// return". The log keeps running and the *nodes* degrade -- so an unreachable
// witness must never stop a log from publishing.

// fakeProofs answers with a fixed proof and records what was asked for.
type fakeProofs struct {
	mu   sync.Mutex
	from []int64
}

func (f *fakeProofs) ConsistencyProof(old int64) ([][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.from = append(f.from, old)
	if old == 0 {
		return nil, nil
	}
	return [][]byte{make([]byte, 32)}, nil
}

func (f *fakeProofs) asked() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.from...)
}

// witnessServer answers add-checkpoint with `handler`, and records every body.
func witnessServer(t *testing.T, handler func(w http.ResponseWriter, body string)) (
	url string, bodies func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := new(strings.Builder)
		_, _ = raw.Write(nil)
		buf := make([]byte, r.ContentLength)
		read := 0
		for read < len(buf) {
			n, err := r.Body.Read(buf[read:])
			read += n
			if err != nil {
				break
			}
		}
		mu.Lock()
		seen = append(seen, string(buf[:read]))
		mu.Unlock()
		handler(w, string(buf[:read]))
	}))
	t.Cleanup(server.Close)
	return server.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// answering is a witness that cosigns whatever it is given.
func answering(t *testing.T, name string) (string, func() []string) {
	t.Helper()
	return witnessServer(t, func(w http.ResponseWriter, body string) {
		_, checkpoint, _ := strings.Cut(body, "\n\n")
		text, _, err := note.Split(checkpoint)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		line, err := cosign.Sign(text, "witness.example/"+name, key(t, name), someInstant)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(line + "\n"))
	})
}

func clientFor(t *testing.T, name, url string) *Client {
	t.Helper()
	return &Client{Name: name, URL: url,
		Key: note.CosignerVerifierKey("witness.example/"+name, public(t, key(t, name)))}
}

func TestEveryWitnessThatAnswersIsOnTheCheckpoint(t *testing.T) {
	signed, _ := aCheckpoint(t)
	firstURL, _ := answering(t, "one")
	secondURL, _ := answering(t, "two")
	proofs := &fakeProofs{}

	s := NewSubmitter([]*Client{clientFor(t, "one", firstURL), clientFor(t, "two", secondURL)},
		proofs, nil)
	got, err := s.Cosign(signed)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Count(got, "\n—") != 3 { // the log's own line plus two witnesses
		t.Errorf("expected two cosignatures appended:\n%s", got)
	}
	if !strings.HasPrefix(got, signed) {
		t.Error("the log's own checkpoint and signature must be left exactly as they were")
	}
	// First contact starts at zero and learns from there.
	for _, from := range proofs.asked() {
		if from != 0 {
			t.Errorf("first contact asked for a proof from %d, want 0", from)
		}
	}
}

// T6: a witness that is down must not stop the log. The checkpoint goes out
// with whatever corroboration was available, and the nodes decide what that is
// worth.
func TestAnUnreachableWitnessDoesNotStopTheLog(t *testing.T) {
	signed, _ := aCheckpoint(t)
	liveURL, _ := answering(t, "one")

	s := NewSubmitter([]*Client{
		clientFor(t, "one", liveURL),
		clientFor(t, "two", "http://127.0.0.1:1"), // nothing listening
	}, &fakeProofs{}, nil)

	got, err := s.Cosign(signed)
	if err != nil {
		t.Fatalf("an unreachable witness stopped the log: %v", err)
	}
	if strings.Count(got, "\n—") != 2 {
		t.Errorf("the reachable witness's cosignature should still be here:\n%s", got)
	}
}

// And with every witness down the log still publishes -- uncosigned, which no
// verifier will accept, which is exactly T6's "nodes hold last good". A log
// that stopped writing instead would turn a witness outage into a log outage.
func TestEveryWitnessDownStillPublishes(t *testing.T) {
	signed, _ := aCheckpoint(t)
	s := NewSubmitter([]*Client{clientFor(t, "one", "http://127.0.0.1:1")},
		&fakeProofs{}, nil)

	got, err := s.Cosign(signed)
	if err != nil {
		t.Fatalf("a witness outage became a log outage: %v", err)
	}
	if got != signed {
		t.Errorf("the checkpoint should be published as the log signed it:\n%s", got)
	}
}

// 409 is how a log discovers where a witness actually is. The retry proves
// consistency from the size the witness named, and it is the same round trip
// that makes first contact work: start at zero, be corrected, prove from there.
func TestAConflictIsRetriedFromTheSizeTheWitnessNames(t *testing.T) {
	signed, body := aCheckpoint(t)
	var attempts int
	url, bodies := witnessServer(t, func(w http.ResponseWriter, _ string) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Content-Type", "text/x.tlog.size")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte("20852014\n"))
			return
		}
		line, err := cosign.Sign(body, "witness.example/one", key(t, "one"), someInstant)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write([]byte(line + "\n"))
	})
	proofs := &fakeProofs{}

	s := NewSubmitter([]*Client{clientFor(t, "one", url)}, proofs, nil)
	got, err := s.Cosign(signed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, "\n—") != 2 {
		t.Errorf("the retry's cosignature is missing:\n%s", got)
	}
	if asked := proofs.asked(); len(asked) != 2 || asked[1] != 20852014 {
		t.Errorf("proofs asked from %v, want the second from 20852014", asked)
	}
	if sent := bodies(); len(sent) != 2 || !strings.HasPrefix(sent[1], "old 20852014\n") {
		t.Errorf("the retry did not start where the witness said it was:\n%q", sent)
	}
}

// What a witness accepted is remembered, so the next checkpoint proves from
// there rather than starting at zero and collecting another conflict on every
// single publish.
func TestTheWitnessSizeIsRemembered(t *testing.T) {
	signed, body := aCheckpoint(t)
	var attempts int
	url, _ := witnessServer(t, func(w http.ResponseWriter, _ string) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Content-Type", "text/x.tlog.size")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte("20852014\n"))
			return
		}
		line, _ := cosign.Sign(body, "witness.example/one", key(t, "one"), someInstant)
		_, _ = w.Write([]byte(line + "\n"))
	})
	proofs := &fakeProofs{}

	s := NewSubmitter([]*Client{clientFor(t, "one", url)}, proofs, nil)
	if _, err := s.Cosign(signed); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Cosign(signed); err != nil {
		t.Fatal(err)
	}

	asked := proofs.asked()
	if len(asked) != 3 {
		t.Fatalf("proofs asked = %v, want three: zero, the corrected size, then the "+
			"size the witness accepted", asked)
	}
	if asked[0] != 0 || asked[1] != 20852014 {
		t.Errorf("the first round asked from %v, want 0 then 20852014", asked[:2])
	}
	// The witness cosigned 20852163, so that is where the next one starts --
	// not zero, and not the older size the conflict named.
	if asked[2] != 20852163 {
		t.Errorf("the second checkpoint asked from %d, want the size the witness "+
			"accepted (20852163)", asked[2])
	}
}

// A witness that keeps conflicting is given up on for this round rather than
// retried forever; the next checkpoint tries again.
func TestARepeatedConflictIsNotRetriedForever(t *testing.T) {
	signed, _ := aCheckpoint(t)
	var attempts int
	url, _ := witnessServer(t, func(w http.ResponseWriter, _ string) {
		attempts++
		w.Header().Set("Content-Type", "text/x.tlog.size")
		w.WriteHeader(http.StatusConflict)
		_, _ = fmt.Fprintf(w, "%d\n", 20852014+attempts)
	})

	s := NewSubmitter([]*Client{clientFor(t, "one", url)}, &fakeProofs{}, nil)
	if _, err := s.Cosign(signed); err != nil {
		t.Fatal(err)
	}
	if attempts > 2 {
		t.Errorf("%d attempts for one checkpoint; a conflicting witness must not be "+
			"retried in a loop", attempts)
	}
}

// Every refusal reaches the operator. A log quietly failing to get cosignatures
// looks exactly like a healthy log until the nodes start degrading.
func TestRefusalsAreReported(t *testing.T) {
	signed, _ := aCheckpoint(t)
	url, _ := witnessServer(t, func(w http.ResponseWriter, _ string) {
		w.WriteHeader(http.StatusForbidden)
	})
	var reported []string
	s := NewSubmitter([]*Client{clientFor(t, "one", url)}, &fakeProofs{},
		func(err error) { reported = append(reported, err.Error()) })

	if _, err := s.Cosign(signed); err != nil {
		t.Fatal(err)
	}
	if len(reported) != 1 || !strings.Contains(reported[0], "does not trust") {
		t.Errorf("the refusal should have been reported: %v", reported)
	}
}
