package ots

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Obtaining a proof. `POST <calendar>/digest` with the raw digest returns a
// bare timestamp tree -- no magic, no version, no file-hash op, because the
// client is expected to know what it asked about.
//
// That asymmetry is why this package still has no serializer: a detached file
// is a fixed header followed by exactly those bytes, so building one is
// concatenation. And whatever is concatenated is then **parsed back and
// walked** before it is returned, so the writer checks its work with the
// reader -- and the reader is the part that was validated against the
// reference implementation's own bytes.

func calendarResponse(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"anchors", "calendar-response.bin"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func bodyDigest(t *testing.T) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(checkpointBody(t)))
	return sum[:]
}

// A calendar that answers the way the real ones do.
func fakeCalendar(t *testing.T, response []byte) (*httptest.Server, func() string) {
	t.Helper()
	var seen string
	var accept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Method + " " + r.URL.Path
		accept = r.Header.Get("Accept")
		_ = accept
		raw := make([]byte, 64)
		n, _ := r.Body.Read(raw)
		if r.URL.Path != "/digest" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if n != sha256.Size {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)
	return server, func() string { return seen }
}

func TestStampBuildsAProofThisPackageCanRead(t *testing.T) {
	server, seen := fakeCalendar(t, calendarResponse(t))
	digest := bodyDigest(t)

	raw, err := Stamp(digest, []string{server.URL})
	if err != nil {
		t.Fatalf("stamping: %v", err)
	}
	if seen() != "POST /digest" {
		t.Errorf("asked the calendar %q, want POST /digest", seen())
	}

	// The test that matters: what was written parses and walks, under the
	// reader that agrees with the reference implementation.
	report, err := CheckAnchor(raw, checkpointBody(t))
	if err != nil {
		t.Fatalf("what Stamp wrote does not check out: %v", err)
	}
	if report.Pending != 1 {
		t.Errorf("pending = %d, want the calendar's promise", report.Pending)
	}
	if report.Earliest != nil {
		t.Error("a freshly stamped proof is not confirmed by anything yet")
	}
}

// Several calendars, one file. Merging is `0xff` before every branch but the
// last, which is the format's own shape -- and the result is still parsed back
// before it is returned.
func TestStampMergesSeveralCalendars(t *testing.T) {
	first, _ := fakeCalendar(t, calendarResponse(t))
	second, _ := fakeCalendar(t, calendarResponse(t))

	raw, err := Stamp(bodyDigest(t), []string{first.URL, second.URL})
	if err != nil {
		t.Fatal(err)
	}
	report, err := CheckAnchor(raw, checkpointBody(t))
	if err != nil {
		t.Fatalf("a merged proof does not check out: %v", err)
	}
	if report.Pending != 2 {
		t.Errorf("pending = %d, want one per calendar", report.Pending)
	}
}

// One calendar being down is not a failure: the point of listing several is
// that any of them may be unreachable.
func TestOneCalendarDownIsSurvivable(t *testing.T) {
	live, _ := fakeCalendar(t, calendarResponse(t))

	raw, err := Stamp(bodyDigest(t), []string{"http://127.0.0.1:1", live.URL})
	if err != nil {
		t.Fatalf("one unreachable calendar stopped the stamp: %v", err)
	}
	if _, err := CheckAnchor(raw, checkpointBody(t)); err != nil {
		t.Fatal(err)
	}
}

// Every calendar down is a failure, because there is nothing to write.
func TestNoCalendarsMeansNoProof(t *testing.T) {
	if _, err := Stamp(bodyDigest(t), []string{"http://127.0.0.1:1"}); err == nil {
		t.Fatal("a proof was produced with no calendar answering")
	}
}

// A calendar that answers with something that is not a timestamp over the
// digest we asked about must be refused rather than written to disk. A file
// that does not chain is worse than no file: it looks like evidence of an edit.
func TestACalendarThatAnswersNonsenseIsRefused(t *testing.T) {
	server, _ := fakeCalendar(t, []byte("this is not a timestamp tree"))

	_, err := Stamp(bodyDigest(t), []string{server.URL})
	if err == nil {
		t.Fatal("nonsense from a calendar was written as a proof")
	}
	if !strings.Contains(err.Error(), "calendar") {
		t.Errorf("the error should name the calendar: %v", err)
	}
}
