package logserver

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

type watchedBody struct {
	io.Reader
	reads int
}

func (b *watchedBody) Read(p []byte) (int, error) {
	b.reads++
	return b.Reader.Read(p)
}

func requestFrom(s *Server, host, forwarded string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, AddPath, body)
	r.RemoteAddr = host
	r.Header.Set("Content-Type", ContentType)
	r.Header.Set("X-Forwarded-For", forwarded)
	r.Header.Set("Forwarded", "for="+forwarded)
	r.Header.Set("X-Real-IP", forwarded)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestARateLimitedRequestIsRefusedBeforeItsBodyOrReplay(t *testing.T) {
	s, anchor, _ := seededServer(t, WithRateLimit(0.5, 1))
	s.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	if w := requestFrom(s, "192.0.2.1:1111", "", bytes.NewReader([]byte("garbage"))); w.Code != http.StatusBadRequest {
		t.Fatalf("first request: %d %s", w.Code, w.Body)
	}
	count := countApplications(s)
	body := &watchedBody{Reader: bytes.NewReader(anEnroll(t, anchor, "rate-refused", uint64(s.store.Size())))}
	before := s.store.Size()
	w := requestFrom(s, "192.0.2.1:2222", "198.51.100.4", body)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("exhausted source: status %d, want 429", w.Code)
	}
	if retry, err := strconv.Atoi(w.Header().Get("Retry-After")); err != nil || retry != 2 {
		t.Errorf("Retry-After = %q, want 2 seconds", w.Header().Get("Retry-After"))
	}
	if body.reads != 0 || *count != 0 || s.store.Size() != before {
		t.Errorf("refused at the door: %d body reads, %d entry applications, size %d -> %d",
			body.reads, *count, before, s.store.Size())
	}
}

func TestSourcesHaveSeparateBucketsAndRefillOnlyToTheirBurst(t *testing.T) {
	s, _, _ := seededServer(t, WithRateLimit(0.5, 2))
	at := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return at }
	for _, host := range []string{"192.0.2.1", "[2001:db8::1]"} {
		for i, want := range []int{400, 400, 429} {
			w := requestFrom(s, fmt.Sprintf("%s:%d", host, 1000+i), fmt.Sprintf("198.51.100.%d", i), nil)
			if w.Code != want {
				t.Fatalf("%s request %d: %d, want %d", host, i, w.Code, want)
			}
		}
	}
	at = at.Add(time.Second)
	w := requestFrom(s, "192.0.2.1:3000", "new-proxy-client", nil)
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("half-refilled bucket: %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	at = at.Add(time.Second)
	if w := requestFrom(s, "192.0.2.1:3000", "", nil); w.Code != 400 {
		t.Fatalf("one refilled token: %d", w.Code)
	}
	if w := requestFrom(s, "192.0.2.1:3000", "", nil); w.Code != 429 {
		t.Fatalf("refilled token spent twice: %d", w.Code)
	}
	at = at.Add(time.Hour)
	for i, want := range []int{400, 400, 429} {
		if w := requestFrom(s, "192.0.2.1:3000", "", nil); w.Code != want {
			t.Fatalf("long-idle request %d: %d, want %d", i, w.Code, want)
		}
	}
}

func TestAServerRefusesInvalidRateLimits(t *testing.T) {
	s, anchor, origin := seededServer(t)
	for _, c := range []struct {
		rate  float64
		burst int
	}{
		{0, 1}, {-1, 1}, {math.NaN(), 1}, {math.Inf(1), 1}, {1, 0}, {1, -1},
	} {
		if _, err := New(s.store, s.dir, origin, logKey(t), anchor, WithRateLimit(c.rate, c.burst)); err == nil {
			t.Errorf("accepted rate %v and burst %d", c.rate, c.burst)
		}
	}
}

func TestManySourcesCannotGrowTheBucketMapPastItsBound(t *testing.T) {
	s, _, _ := seededServer(t)
	at := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return at }
	for i := 0; i < 2*maxSources; i++ {
		host := fmt.Sprintf("198.51.%d.%d:1234", i/256, i%256)
		want := http.StatusBadRequest
		if i >= maxSources {
			want = http.StatusTooManyRequests
		}
		if w := requestFrom(s, host, "", nil); w.Code != want {
			t.Fatalf("source %d: %d, want %d", i, w.Code, want)
		}
		if len(s.buckets) > maxSources {
			t.Fatalf("%d sources grew the bucket map to %d, bound %d", i+1, len(s.buckets), maxSources)
		}
	}
	if len(s.buckets) != maxSources {
		t.Fatalf("tracked %d sources, want %d", len(s.buckets), maxSources)
	}
	// Existing sources keep their tokens at capacity; refusing a new source
	// must not replace an active bucket and give that source a fresh burst.
	if w := requestFrom(s, "198.51.0.0:5678", "", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("existing source at map capacity: %d", w.Code)
	}
	at = at.Add(bucketIdle)
	if w := requestFrom(s, "203.0.113.1:1234", "", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("idle buckets were not evicted: fresh source got %d, want 400", w.Code)
	}
	if len(s.buckets) != 1 {
		t.Fatalf("idle buckets remain: map has %d sources, want 1", len(s.buckets))
	}
}
