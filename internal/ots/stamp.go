package ots

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultCalendars are the public OpenTimestamps calendars.
//
// They are aggregators, not authorities: a calendar's answer is a promise to
// include a value in a future Bitcoin block, and the proof it hands back is
// checkable without it afterwards. Listing several is the whole redundancy
// story -- any of them may be down, and a stamp only needs one.
var DefaultCalendars = []string{
	"https://alice.btc.calendar.opentimestamps.org",
	"https://bob.btc.calendar.opentimestamps.org",
	"https://finney.btc.calendar.opentimestamps.org",
}

// CalendarTimeout bounds one submission.
const CalendarTimeout = 15 * time.Second

// maxCalendarResponse matches the reference client's limit.
const maxCalendarResponse = 10000

// Stamp obtains an OpenTimestamps proof over `digest` and returns the bytes of
// a detached `.ots` file.
//
// Building the file is concatenation, not serialization. A calendar answers
// `POST /digest` with a bare timestamp tree -- no magic, no version, no
// file-hash op, because the client knows what it asked about -- and a detached
// file is a fixed header followed by exactly those bytes. Several calendars
// merge with the format's own branch marker: `0xff` before every branch but
// the last.
//
// That keeps this package free of a serializer, which matters: a writer built
// only for this would be checked against its own reader and nothing else.
// Instead the result is **parsed back and walked** before it is returned, by
// the reader that was validated against the reference implementation's bytes.
// A file that does not chain is never written, because a proof that does not
// chain looks exactly like evidence of an edit.
func Stamp(digest []byte, calendars []string) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, proofErrorf("a stamp is over a %d-byte sha256 digest, got %d",
			sha256.Size, len(digest))
	}
	if len(calendars) == 0 {
		return nil, proofErrorf("no calendars to ask")
	}

	var trees [][]byte
	var failures []string
	for _, calendar := range calendars {
		tree, err := submit(calendar, digest)
		if err != nil {
			// One calendar being down is not a failure; that is why there are
			// several.
			failures = append(failures, err.Error())
			continue
		}
		trees = append(trees, tree)
	}
	if len(trees) == 0 {
		return nil, proofErrorf("no calendar answered: %s", strings.Join(failures, "; "))
	}

	raw := detach(digest, trees)

	// Check the work with the reader before handing it back.
	proof, err := Parse(raw)
	if err != nil {
		return nil, proofErrorf("the calendar answers did not make a readable proof "+
			"(%v); nothing was written", err)
	}
	if _, err := proof.Walk(digest); err != nil {
		return nil, proofErrorf("the calendar answers do not chain from what was "+
			"submitted (%v); nothing was written", err)
	}
	return raw, nil
}

// detach wraps calendar trees in a detached-file header.
func detach(digest []byte, trees [][]byte) []byte {
	var out bytes.Buffer
	out.Write(magic)
	out.WriteByte(majorVersion)
	out.WriteByte(tagSHA256)
	out.Write(digest)
	for i, tree := range trees {
		if i < len(trees)-1 {
			out.WriteByte(markerFork)
		}
		out.Write(tree)
	}
	return out.Bytes()
}

// submit asks one calendar to timestamp a digest.
func submit(calendar string, digest []byte) ([]byte, error) {
	url := strings.TrimSuffix(calendar, "/") + "/digest"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(digest))
	if err != nil {
		return nil, fmt.Errorf("calendar %s: %w", calendar, err)
	}
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "norn")

	client := &http.Client{Timeout: CalendarTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calendar %s is unreachable: %w", calendar, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("calendar %s answered %d", calendar, resp.StatusCode)
	}
	tree, err := io.ReadAll(io.LimitReader(resp.Body, maxCalendarResponse+1))
	if err != nil {
		return nil, fmt.Errorf("calendar %s: %w", calendar, err)
	}
	if len(tree) > maxCalendarResponse {
		return nil, fmt.Errorf("calendar %s answered with more than %d bytes",
			calendar, maxCalendarResponse)
	}
	if len(tree) == 0 {
		return nil, fmt.Errorf("calendar %s answered with nothing", calendar)
	}
	return tree, nil
}
