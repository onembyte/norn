package logserver

import (
	"math"
	"net"
	"net/netip"
	"time"
)

// The source map has a fixed ceiling; idle sources stay at least ten minutes.
const (
	maxSources = 4096
	bucketIdle = 10 * time.Minute
)

// DefaultRate and DefaultBurst allow one submission per second with a burst
// of 32, generous for an operator submitting a handful of entries a day.
const (
	DefaultRate  = 1.0
	DefaultBurst = 32
)

// Option configures a server before it starts serving requests.
type Option func(*Server)

// WithRateLimit sets the per-source token refill rate in entries per second
// and burst capacity. New refuses nonpositive or nonfinite limits.
func WithRateLimit(rate float64, burst int) Option {
	return func(s *Server) { s.rate, s.burst = rate, burst }
}

type tokenBucket struct {
	host   string
	tokens float64
	at     time.Time
}

// limit spends a token before any body read or fold, keyed only by the remote
// IPv4 address or IPv6 /64, so rotating addresses within one prefix cannot
// exhaust the source map. Proxy headers are untrusted and ignored: behind a
// reverse proxy every client shares its bucket, the safe default until a
// later row defines a trusted-proxy option. A separate lock keeps slow bodies
// and appends from delaying refusals at the door.
func (s *Server) limit(remote string) int {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote // A bare host still gets one bucket, never a proxy's claim.
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if addr.Is4() {
			host = addr.String()
		} else {
			host = netip.PrefixFrom(addr.WithZone(""), 64).Masked().String()
		}
	}
	s.bucketMu.Lock()
	defer s.bucketMu.Unlock()
	now := s.now()
	// Evicting earlier than a full refill would hand a slow-rate source new
	// tokens. The idle horizon must cover both that refill and ten minutes.
	idle := math.Max(bucketIdle.Seconds(), float64(s.burst)/s.rate)
	s.evictIdle(now, idle)
	element := s.buckets[host]
	if element == nil {
		if len(s.buckets) >= maxSources {
			// Do not replace active buckets: rotating source addresses would
			// otherwise reset their bursts. New sources wait for idle space.
			oldest := s.sources.Front().Value.(*tokenBucket)
			return retrySeconds(idle - now.Sub(oldest.at).Seconds())
		}
		b := &tokenBucket{host: host, tokens: float64(s.burst), at: now}
		element = s.sources.PushBack(b)
		s.buckets[host] = element
	}
	b := element.Value.(*tokenBucket)
	if elapsed := now.Sub(b.at).Seconds(); elapsed > 0 {
		b.tokens = math.Min(float64(s.burst), b.tokens+elapsed*s.rate)
		b.at = now
	}
	s.sources.MoveToBack(element)
	if b.tokens < 1 {
		return retrySeconds((1 - b.tokens) / s.rate)
	}
	b.tokens--
	return 0
}

// evictIdle removes the oldest sources first, so a request does not scan the
// whole map. Both the map and this list stay within the same fixed ceiling.
func (s *Server) evictIdle(now time.Time, idle float64) {
	for first := s.sources.Front(); first != nil; first = s.sources.Front() {
		b := first.Value.(*tokenBucket)
		if now.Sub(b.at).Seconds() < idle {
			return
		}
		delete(s.buckets, b.host)
		s.sources.Remove(first)
	}
}

// Retry-After is a positive whole number of seconds. Cap the advisory wait
// so even a tiny positive rate produces a finite header on 32-bit hosts.
func retrySeconds(seconds float64) int {
	return int(math.Max(1, math.Min(math.MaxInt32, math.Ceil(seconds))))
}
