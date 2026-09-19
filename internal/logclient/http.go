package logclient

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// MaxFetchBytes bounds any single response. A verifier fetches from a log it
// does not trust; without a limit, answering a request is enough to exhaust
// it. Generous against a full tile (8 KiB) or entry bundle.
const MaxFetchBytes = 8 << 20

// HTTP serves a log from a base URL over plain HTTP. No server-side logic is
// required of the other end: a static file server is the whole contract, which
// is what makes a log cheap to host and easy to mirror.
type HTTP string

// Fetch implements Fetcher.
func (h HTTP) Fetch(p string) ([]byte, error) {
	// Refuse a path that escapes the log root before it is ever sent: a
	// verifier should not be asking for it, and a proxy might honour it.
	clean := path.Clean("/" + p)
	if strings.TrimPrefix(clean, "/") != p {
		return nil, logErrorf("refusing to fetch %q: not a log-relative path", p)
	}
	base, err := url.Parse(string(h))
	if err != nil {
		return nil, logErrorf("bad log URL: %v", err)
	}
	base.Path = path.Join(base.Path, p)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(base.String())
	if err != nil {
		return nil, logErrorf("fetching %s: %v", p, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, logErrorf("fetching %s: %s", p, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxFetchBytes+1))
	if err != nil {
		return nil, logErrorf("reading %s: %v", p, err)
	}
	if len(body) > MaxFetchBytes {
		return nil, logErrorf("%s exceeds %d bytes", p, MaxFetchBytes)
	}
	return body, nil
}

// Open returns the Fetcher for a location: an HTTP(S) URL, or a directory.
func Open(location string) (Fetcher, error) {
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return HTTP(location), nil
	}
	return Dir(location), nil
}

// SubmitPath is §7's endpoint, relative to the log's prefix.
const SubmitPath = "add"

// Submit POSTs entry bytes to a log and returns the receipt it signs (§7).
//
// This is the one thing a verifier never does, so it stands apart from
// Fetcher: reading a log needs only "give me the bytes at this path", and
// keeping that interface narrow is what lets a peer serve a log over gossip
// without also being able to accept submissions.
func Submit(base string, raw []byte) (receipt string, status int, err error) {
	endpoint, err := url.JoinPath(base, SubmitPath)
	if err != nil {
		return "", 0, logErrorf("building the submission URL: %v", err)
	}
	resp, err := http.Post(endpoint, "application/cbor", bytes.NewReader(raw))
	if err != nil {
		return "", 0, logErrorf("submitting: %v", err)
	}
	defer resp.Body.Close()

	// A log's answer is as untrusted as its files: bound it.
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxFetchBytes))
	if err != nil {
		return "", resp.StatusCode, logErrorf("reading the response: %v", err)
	}
	return string(body), resp.StatusCode, nil
}
