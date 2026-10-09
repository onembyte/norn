package logserver

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
)

// The seam counts every entry handed to the fold, including any replay used
// to compute the receipt's deadline, rather than counting requests to add.
func countApplications(s *Server) *int {
	count := new(int)
	s.apply = func(p *replay.Replayer, entries ...[]byte) *state.State {
		*count += len(entries)
		return p.Apply(entries...)
	}
	return count
}

func submit(s *Server, raw []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, AddPath, bytes.NewReader(raw))
	r.Header.Set("Content-Type", ContentType)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func sameFoldAsStore(t *testing.T, s *Server) {
	t.Helper()
	entries, err := s.entries()
	if err != nil {
		t.Fatal(err)
	}
	want, err := replay.Replay(s.anchor, entries).MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.fold.State().MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("held fold differs byte for byte from replay of %d stored entries", len(entries))
	}
}

func TestASubmissionAppliesOneEntryRegardlessOfHistory(t *testing.T) {
	s, anchor, _ := seededServer(t)
	count := countApplications(s)
	w := submit(s, anEnroll(t, anchor, "one-application", uint64(s.store.Size())))
	if w.Code != http.StatusOK {
		t.Fatalf("submission: %d %s", w.Code, w.Body)
	}
	if *count != 1 {
		t.Fatalf("submission to %d prior entries applied %d entries, want 1", s.store.Size()-1, *count)
	}
	*count = 0
	if w := submit(s, []byte("garbage")); w.Code != http.StatusBadRequest || *count != 0 {
		t.Fatalf("malformed submission: status %d, %d applications", w.Code, *count)
	}
}

// A refusal changes the candidate's size and seen set even when no device was
// changed. Comparing after each request catches either of those leaking.
func TestTheHeldFoldEqualsStoredReplayAfterAcceptedAndRefusedSubmissions(t *testing.T) {
	s, anchor, _ := seededServer(t)
	sameFoldAsStore(t, s)
	first := anEnroll(t, anchor, "fold-first", uint64(s.store.Size()))
	refused := anEnroll(t, anchor, "nas", uint64(s.store.Size()))
	for _, c := range []struct {
		raw  []byte
		want int
	}{
		{first, http.StatusOK},
		{refused, http.StatusConflict},
		{refused, http.StatusConflict},
		{[]byte("garbage"), http.StatusBadRequest},
		{first, http.StatusOK},
		{anEnroll(t, anchor, "fold-second", uint64(s.store.Size())), http.StatusOK},
	} {
		if w := submit(s, c.raw); w.Code != c.want {
			t.Fatalf("submission: %d %s, want %d", w.Code, w.Body, c.want)
		}
		sameFoldAsStore(t, s)
	}
}

func TestConcurrentAcceptedAndRefusedSubmissionsKeepTheHeldFold(t *testing.T) {
	s, anchor, _ := seededServer(t)
	const n = 8
	raws := make([][]byte, n)
	for i := range raws {
		id := fmt.Sprintf("held-concurrent-%d", i)
		if i%2 == 0 {
			id = "nas"
		}
		raws[i] = anEnroll(t, anchor, id, uint64(s.store.Size()))
	}
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range raws {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = submit(s, raws[i]).Code
		}(i)
	}
	wg.Wait()
	for i, code := range codes {
		want := http.StatusOK
		if i%2 == 0 {
			want = http.StatusConflict
		}
		if code != want {
			t.Errorf("submission %d: %d, want %d", i, code, want)
		}
	}
	sameFoldAsStore(t, s)
}

func TestAPersistedAppendWithAFailedCheckpointStillAdvancesTheFold(t *testing.T) {
	s, anchor, _ := seededServer(t)
	// The authoritative bundle can be written, but publishing the derived
	// checkpoint fails. Store.Append has already advanced its tree then.
	path := filepath.Join(s.dir, "checkpoint")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if w := submit(s, anEnroll(t, anchor, "persisted", uint64(s.store.Size()))); w.Code != http.StatusInternalServerError {
		t.Fatalf("append with a failed checkpoint: %d %s", w.Code, w.Body)
	}
	sameFoldAsStore(t, s)
	before := s.store.Size()
	if w := submit(s, anEnroll(t, anchor, "needs-repair", uint64(before))); w.Code != http.StatusInternalServerError {
		t.Fatalf("writing after a store error: %d %s", w.Code, w.Body)
	}
	if s.store.Size() != before {
		t.Fatal("the server kept writing after an incomplete append")
	}
}

func TestReceiptsUseTheHeldNetworksMMDWithoutReplaying(t *testing.T) {
	s, anchor, origin := seededServer(t)
	s.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	count := countApplications(s)
	raw, err := s.store.Entry(0)
	if err != nil {
		t.Fatal(err)
	}
	w := submit(s, raw)
	if w.Code != http.StatusOK {
		t.Fatalf("resubmission: %d %s", w.Code, w.Body)
	}
	entries, err := s.entries()
	if err != nil {
		t.Fatal(err)
	}
	mmd := replay.Replay(anchor, entries).Params["mmd"].(uint64)
	want, err := note.ReceiptText(origin, entry.LeafHash(raw), uint64(s.now().Unix())+mmd)
	if err != nil {
		t.Fatal(err)
	}
	text, _, err := note.Split(w.Body.String())
	if err != nil || text != want {
		t.Fatalf("receipt deadline differs from the network mmd: %v, %q", err, text)
	}
	if *count != 0 {
		t.Fatalf("an idempotent receipt applied %d entries, want 0", *count)
	}
}
