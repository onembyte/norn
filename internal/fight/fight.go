// Package fight notices when something keeps putting a key back.
//
// `ENFORCEMENT.md` part 3: in watchdog mode somebody else owns the peer table,
// and Norn evicts what the log does not prove. If the same key comes back
// again and again, the other writer is not misconfigured — it is *disagreeing*,
// and an operator needs to know that their control plane and their log have
// different ideas about who belongs on the network.
//
// The distinction matters because the two look identical one eviction at a
// time. A single eviction is routine; three in a minute is a fight.
package fight

import (
	"sort"
	"time"

	"github.com/onembyte/norn/internal/peertable"
)

// Defaults from `ENFORCEMENT.md` part 3.
const (
	DefaultThreshold = 3
	DefaultWindow    = 60 * time.Second
	// MaxTracked bounds the memory a long-running daemon spends on this. An
	// attacker cycling fresh keys must not be able to grow it without limit:
	// `nornd` runs for months on a Pi.
	MaxTracked = 4096
)

// Detector counts recent evictions per key.
type Detector struct {
	threshold int
	window    time.Duration
	seen      map[peertable.Key][]time.Time
	// declared remembers which keys have already been reported, so a fight is
	// announced when it starts rather than on every subsequent eviction.
	declared map[peertable.Key]bool
}

// New returns a detector. Zero values take the documented defaults.
func New(threshold int, window time.Duration) *Detector {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	if window <= 0 {
		window = DefaultWindow
	}
	return &Detector{
		threshold: threshold, window: window,
		seen:     map[peertable.Key][]time.Time{},
		declared: map[peertable.Key]bool{},
	}
}

// Record notes one eviction and reports how many have happened inside the
// window, and whether this is the moment the fight becomes visible.
//
// `started` is true exactly once per fight, so a caller can act on it — bring
// an interface down, page somebody — without doing it again every poll.
func (d *Detector) Record(key peertable.Key, at time.Time) (count int, started bool) {
	cutoff := at.Add(-d.window)
	times := append(d.seen[key], at)
	kept := times[:0]
	for _, when := range times {
		if when.After(cutoff) {
			kept = append(kept, when)
		}
	}
	d.seen[key] = kept
	d.evict(at)

	count = len(kept)
	if count < d.threshold {
		// A run that dies down stops being a fight, so the next one is
		// announced afresh.
		delete(d.declared, key)
		return count, false
	}
	if d.declared[key] {
		return count, false
	}
	d.declared[key] = true
	return count, true
}

// Fighting reports whether a key is currently in a declared fight.
func (d *Detector) Fighting(key peertable.Key) bool { return d.declared[key] }

// Tracked is how many keys the detector is holding, for tests and metrics.
func (d *Detector) Tracked() int { return len(d.seen) }

// Threshold and Window report the configured limits, so a message can quote
// them rather than restating a default that may not apply.
func (d *Detector) Threshold() int        { return d.threshold }
func (d *Detector) Window() time.Duration { return d.window }

// evict drops keys with nothing left in the window, and if the map is still
// over the cap, the keys whose last eviction is oldest.
func (d *Detector) evict(now time.Time) {
	cutoff := now.Add(-d.window)
	for key, times := range d.seen {
		if len(times) == 0 || !times[len(times)-1].After(cutoff) {
			delete(d.seen, key)
			delete(d.declared, key)
		}
	}
	if len(d.seen) <= MaxTracked {
		return
	}
	type aged struct {
		key  peertable.Key
		last time.Time
	}
	all := make([]aged, 0, len(d.seen))
	for key, times := range d.seen {
		all = append(all, aged{key, times[len(times)-1]})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last.Before(all[j].last) })
	for _, entry := range all[:len(d.seen)-MaxTracked] {
		delete(d.seen, entry.key)
		delete(d.declared, entry.key)
	}
}
