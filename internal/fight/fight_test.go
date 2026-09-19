package fight

import (
	"testing"
	"time"

	"github.com/onembyte/norn/internal/peertable"
)

func key(b byte) peertable.Key {
	var k peertable.Key
	for i := range k {
		k[i] = b
	}
	return k
}

// One eviction is routine. Three in a minute is a disagreement between a
// control plane and a log, and somebody has to be told.
func TestAFightIsThreeInAMinute(t *testing.T) {
	d := New(DefaultThreshold, DefaultWindow)
	at := time.Unix(1_800_000_000, 0)

	for i := 1; i <= 2; i++ {
		count, started := d.Record(key(1), at.Add(time.Duration(i)*time.Second))
		if started {
			t.Fatalf("declared a fight after %d eviction(s)", i)
		}
		if count != i {
			t.Errorf("count = %d, want %d", count, i)
		}
	}
	count, started := d.Record(key(1), at.Add(3*time.Second))
	if !started || count != 3 {
		t.Fatalf("count = %d, started = %v; the third eviction is the fight", count, started)
	}
}

// Declared once, not every poll: a caller that brings an interface down on
// `started` must not do it again five times a second.
func TestAFightIsDeclaredOnce(t *testing.T) {
	d := New(3, time.Minute)
	at := time.Unix(1_800_000_000, 0)

	var declarations int
	for i := 0; i < 20; i++ {
		if _, started := d.Record(key(1), at.Add(time.Duration(i)*time.Second)); started {
			declarations++
		}
	}
	if declarations != 1 {
		t.Fatalf("%d declarations for one continuous fight", declarations)
	}
	if !d.Fighting(key(1)) {
		t.Error("the key should still be in a declared fight")
	}
}

// Evictions spread out are not a fight: a device that is revoked, re-enrolled
// and revoked again over an afternoon is an operator at work.
func TestTheWindowSlides(t *testing.T) {
	d := New(3, time.Minute)
	at := time.Unix(1_800_000_000, 0)

	for i := 0; i < 5; i++ {
		_, started := d.Record(key(1), at.Add(time.Duration(i)*30*time.Second))
		if started {
			t.Fatalf("declared a fight from evictions 30s apart (i=%d)", i)
		}
	}
}

// A fight that dies down and returns is a new fight, worth announcing again.
func TestAFightCanEnd(t *testing.T) {
	d := New(3, time.Minute)
	at := time.Unix(1_800_000_000, 0)
	for i := 0; i < 3; i++ {
		d.Record(key(1), at.Add(time.Duration(i)*time.Second))
	}
	if !d.Fighting(key(1)) {
		t.Fatal("no fight declared")
	}

	later := at.Add(10 * time.Minute)
	if _, started := d.Record(key(1), later); started {
		t.Error("one eviction after a quiet spell is not a fight")
	}
	if d.Fighting(key(1)) {
		t.Error("the old fight should have lapsed")
	}
	d.Record(key(1), later.Add(time.Second))
	if _, started := d.Record(key(1), later.Add(2*time.Second)); !started {
		t.Error("a fresh run of evictions is a fresh fight")
	}
}

// Per key, as the design says: two keys evicted once each is not a fight.
func TestKeysAreCountedSeparately(t *testing.T) {
	d := New(3, time.Minute)
	at := time.Unix(1_800_000_000, 0)
	for i, k := range []peertable.Key{key(1), key(2), key(3)} {
		if _, started := d.Record(k, at.Add(time.Duration(i)*time.Second)); started {
			t.Fatal("three different keys evicted once each is not one key fighting")
		}
	}
}

// nornd runs for months on a Pi, and an attacker can mint keys all day.
func TestMemoryIsBounded(t *testing.T) {
	d := New(3, time.Minute)
	at := time.Unix(1_800_000_000, 0)

	for i := 0; i < MaxTracked+500; i++ {
		var k peertable.Key
		k[0], k[1], k[2] = byte(i), byte(i>>8), byte(i>>16)
		d.Record(k, at.Add(time.Duration(i)*time.Millisecond))
	}
	if d.Tracked() > MaxTracked {
		t.Fatalf("tracking %d keys, cap is %d", d.Tracked(), MaxTracked)
	}
	if d.Tracked() == 0 {
		t.Fatal("the detector forgot everything")
	}
}

// Keys that have gone quiet are forgotten even below the cap, so a daemon does
// not accumulate a year of one-off evictions.
func TestQuietKeysAreForgotten(t *testing.T) {
	d := New(3, time.Minute)
	at := time.Unix(1_800_000_000, 0)
	d.Record(key(1), at)
	if d.Tracked() != 1 {
		t.Fatalf("tracked = %d", d.Tracked())
	}
	d.Record(key(2), at.Add(2*time.Minute))
	if d.Tracked() != 1 {
		t.Errorf("tracked = %d; the key from two minutes ago should be gone", d.Tracked())
	}
}

func TestDefaultsAreTheDocumentedOnes(t *testing.T) {
	d := New(0, 0)
	if d.Threshold() != DefaultThreshold || d.Window() != DefaultWindow {
		t.Errorf("defaults are %d in %s, want %d in %s",
			d.Threshold(), d.Window(), DefaultThreshold, DefaultWindow)
	}
}
