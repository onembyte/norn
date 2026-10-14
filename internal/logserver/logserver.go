// Package logserver is the log's write side: the one endpoint a static file
// server cannot provide.
//
// Everything a verifier reads -- tiles, entry bundles, the signed checkpoint --
// is a file on disk, and `PLAN.md`'s gate says plain nginx must be able to
// serve it. What nginx cannot do is accept a submission, so that is all this
// package adds: `POST <prefix>/add` (SPEC §7), returning a signed receipt.
//
// The handler validates submissions against its own replay, and refuses the
// ones that would be rejected. §6 is explicit that this is a courtesy -- it
// keeps the log tidy, and **verifiers MUST NOT rely on it** (THREAT-MODEL G3).
// A log that accepted everything would still be a correct log; a verifier that
// believed this check would be a broken verifier.
package logserver

import (
	"bytes"
	"container/list"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlogstore"
)

// ContentType is what §7 says a submission carries.
const ContentType = "application/cbor"

// AddPath is the submission endpoint, the one Norn-specific path (§6).
const AddPath = "/add"

// Server answers submissions and serves the log directory.
type Server struct {
	store      *tlogstore.Store
	dir        string
	key        ed25519.PrivateKey
	origin     string
	anchor     replay.Anchor
	now        func() time.Time
	fold       *replay.Replayer
	byEntry    map[string]int64
	byPreimage map[[32]byte]int64
	storeErr   error
	rate       float64
	burst      int
	buckets    map[string]*list.Element
	sources    list.List
	bucketMu   sync.Mutex
	// apply counts entry applications in tests without changing replay rules.
	apply func(*replay.Replayer, ...[]byte) *state.State

	// The candidate fold, append and advance share one lock, so a refused
	// candidate never moves the held fold and concurrent writers cannot
	// interleave the store's tree and file updates.
	mu sync.Mutex
}

// New builds a server over an already-open store. The server must be its only
// appender: the held fold and duplicate indexes are built once from that log.
func New(store *tlogstore.Store, dir, origin string, key ed25519.PrivateKey,
	anchor replay.Anchor, opts ...Option) (*Server, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("logserver: the log needs its signing key")
	}
	s := &Server{store: store, dir: dir, key: key, origin: origin,
		anchor: anchor, now: time.Now, apply: (*replay.Replayer).Apply,
		byEntry: make(map[string]int64), byPreimage: make(map[[32]byte]int64),
		buckets: make(map[string]*list.Element),
		rate:    DefaultRate, burst: DefaultBurst}
	for _, opt := range opts {
		opt(s)
	}
	if s.rate <= 0 || math.IsNaN(s.rate) || math.IsInf(s.rate, 0) || s.burst < 1 {
		return nil, errors.New("logserver: rate and burst must be positive and finite")
	}
	entries, err := s.entries()
	if err != nil {
		return nil, err
	}
	s.fold = replay.New(anchor)
	s.apply(s.fold, entries...)
	refused := map[int64]bool{}
	for _, r := range s.fold.State().Rejected {
		refused[int64(r.Index)] = true
	}
	for index, raw := range entries {
		s.remember(raw, int64(index), !refused[int64(index)])
	}
	return s, nil
}

// Handler routes submissions to `/add` and everything else to the files a
// static server would return.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(AddPath, s.handleAdd)
	mux.Handle("/", http.FileServer(http.Dir(s.dir)))
	return mux
}

// handleAdd implements §7.
func (s *Server) handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "submit with POST (SPEC §7)", http.StatusMethodNotAllowed)
		return
	}
	if retry := s.limit(r.RemoteAddr); retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		http.Error(w, "submission rate exceeded (SPEC §7)", http.StatusTooManyRequests)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != ContentType {
		http.Error(w, fmt.Sprintf("Content-Type must be %s, got %q", ContentType, ct),
			http.StatusBadRequest)
		return
	}

	// An entry cannot exceed the profile's cap, so neither may a request body:
	// a log answering a submission must not be exhaustible by sending one.
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cbor.MaxEntryBytes))
	if err != nil {
		http.Error(w, "the submission is larger than an entry may be", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	receipt, status, err := s.add(raw)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, receipt)
}

// add is the decision, separated from the HTTP so that it can be read as the
// procedure §7 describes.
func (s *Server) add(raw []byte) (receipt string, status int, err error) {
	if s.storeErr != nil {
		return "", http.StatusInternalServerError, s.storeErr
	}
	env, err := entry.Decode(raw)
	if err != nil {
		return "", http.StatusBadRequest, fmt.Errorf("not a well-formed entry: %w", err)
	}
	if !bytes.Equal(env.Net, s.anchor.Net) {
		return "", http.StatusBadRequest, errors.New("that entry is for another network")
	}

	// Re-submitting is not an error. A client whose connection dropped after
	// the append has an entry in the log and no receipt, and telling it
	// `dup-entry` would be true but useless.
	if _, found, err := s.indexOf(raw); err != nil {
		return "", http.StatusInternalServerError, err
	} else if found {
		text, err := s.receiptFor(raw)
		return text, http.StatusOK, err
	}

	// A different entry with the same signed content as an applied one is not
	// a resubmission: it is a re-signed copy, and a verifier that keys
	// duplicates on bytes applies it again -- SEC-001, settled by D-070 as
	// `dup-entry` on the signed content. The log refuses it by name, so the
	// only way to re-apply an entry is to sign a new one. A refused entry's
	// content is not indexed: replay judges the genuine entry after a stripped
	// copy on its own (D-078), and so does this door. It is the log's own; a
	// verifier must not rely on it (§6), which is why D-070 and D-078 change
	// replay as well.
	if index, found, err := s.preimageIndexOf(env); err != nil {
		return "", http.StatusInternalServerError, err
	} else if found {
		return "", http.StatusConflict, fmt.Errorf(
			"that entry's signed content is already in the log at index %d; a copy "+
				"under a different signature list is not a new entry (D-070)", index)
	}

	// The courtesy check (§6) folds only the candidate. Clone carries the
	// seen sets as well as the state, so a refusal leaks neither into the log.
	candidate := s.fold.Clone()
	st := s.apply(candidate, raw)
	index := s.store.Size()
	if len(st.Rejected) > 0 {
		if last := st.Rejected[len(st.Rejected)-1]; last.Index == uint64(index) {
			return "", http.StatusConflict, fmt.Errorf(
				"this log's own replay rejects that entry: %s "+
					"(advisory: §6 says a verifier must not rely on this check)", last.Reason)
		}
	}

	if _, err := s.store.Append(raw); err != nil {
		// Append can persist the authoritative bundle before a derived tile
		// or checkpoint fails. Advance only if the entry can be read back;
		// either way, stop writing until reopening repairs the store.
		if stored, readErr := s.store.Entry(index); readErr == nil && bytes.Equal(stored, raw) {
			s.fold = candidate
			s.remember(raw, index, true)
		}
		s.storeErr = fmt.Errorf("logserver: append failed; reopen the store before writing again: %w", err)
		return "", http.StatusInternalServerError, s.storeErr
	}
	s.fold = candidate
	s.remember(raw, index, true)
	text, err := s.receiptFor(raw)
	return text, http.StatusOK, err
}

// receiptFor signs the promise of §7: this leaf will be in a checkpoint issued
// no later than `deadline`.
func (s *Server) receiptFor(raw []byte) (string, error) {
	text, err := note.ReceiptText(s.origin, entry.LeafHash(raw), s.deadline())
	if err != nil {
		return "", err
	}
	return note.Sign(text, s.origin, s.key)
}

// deadline is now + the network's own `mmd`, read from the log's replayed
// state rather than from a flag: the promise's length is a protocol parameter
// (§4.5), and a log that used its own number would be promising something the
// network never agreed to.
func (s *Server) deadline() uint64 {
	mmd := s.fold.State().Params["mmd"].(uint64)
	return uint64(s.now().Unix()) + mmd
}

// entries reads every entry the log holds, in order.
func (s *Server) entries() ([][]byte, error) {
	size := s.store.Size()
	out := make([][]byte, 0, size)
	for index := int64(0); index < size; index++ {
		raw, err := s.store.Entry(index)
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, nil
}

// indexOf finds an entry already in the log by its §4.0 entry hash.
func (s *Server) indexOf(raw []byte) (int64, bool, error) {
	index, found := s.byEntry[string(entry.EntryHash(raw))]
	return index, found, nil
}

// preimageIndexOf finds the first applied entry with the same signed content,
// regardless of its signature list.
func (s *Server) preimageIndexOf(env *entry.Envelope) (int64, bool, error) {
	preimage, err := entry.Preimage(env)
	if err != nil {
		return 0, false, err
	}
	index, found := s.byPreimage[sha256.Sum256(preimage)]
	return index, found, nil
}

// remember builds the duplicate indexes at startup and after an append. The
// first occurrence wins, so a refusal still names the original log index.
// Every stored entry's bytes are indexed; its signed content only when the
// held fold applied it (D-078).
func (s *Server) remember(raw []byte, index int64, applied bool) {
	hash := string(entry.EntryHash(raw))
	if _, found := s.byEntry[hash]; !found {
		s.byEntry[hash] = index
	}
	if !applied {
		return
	}
	env, err := entry.Decode(raw)
	if err != nil {
		return
	}
	preimage, err := entry.Preimage(env)
	if err != nil {
		return
	}
	sum := sha256.Sum256(preimage)
	if _, found := s.byPreimage[sum]; !found {
		s.byPreimage[sum] = index
	}
}

// Status is what a `norn-log` operator sees; it exists so the lab can tell a
// running log from a wedged one without reading files.
type Status struct {
	Origin string `json:"origin"`
	Size   int64  `json:"size"`
}

// StatusJSON reports the log's head as JSON.
func (s *Server) StatusJSON() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Marshal(Status{Origin: s.origin, Size: s.store.Size()})
}
