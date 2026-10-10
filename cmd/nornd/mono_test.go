package main

import (
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/peertable"
)

// D-074 (b), found in review: §15's age is witness time plus monotonic time
// since, and a monotonic reading that stops while the machine is suspended
// makes a node that slept for an hour think its view is an hour younger than
// it is. On Linux nornd reads CLOCK_BOOTTIME, which keeps counting through a
// suspend; elsewhere it uses Go's monotonic reading and the gap is named. A
// suspend cannot be staged in a test, so this pins the clock each platform
// uses and that the reading behaves as a monotonic clock does.
func TestNorndCountsASuspendWhereThePlatformCan(t *testing.T) {
	if got := clockFor("linux"); got.name != "CLOCK_BOOTTIME" || got.id != 7 {
		t.Errorf("on Linux nornd reads %s (id %d); want CLOCK_BOOTTIME (id 7), which counts a suspend",
			got.name, got.id)
	}
	for _, goos := range []string{"darwin", "freebsd", "windows"} {
		if got := clockFor(goos); got.id != noClockID || got.name != goMonotonic {
			t.Errorf("on %s nornd reads %s (id %d); want Go's monotonic reading", goos, got.name, got.id)
		}
	}

	mono, err := monotonic()
	if err != nil {
		t.Fatalf("the %s reading is unavailable here: %v", clockFor(runtime.GOOS).name, err)
	}
	first := mono()
	if first < 0 || first > time.Second {
		t.Errorf("the first reading is %s; a reading starts at zero when nornd does", first)
	}
	time.Sleep(20 * time.Millisecond)
	if second := mono(); second < first+10*time.Millisecond {
		t.Errorf("the reading went from %s to %s across 20ms", first, second)
	}
}

// The clock reaches the agent: a reading build did not hand over would leave
// the agent on its own default, Go's monotonic reading, on every platform.
func TestTheDaemonHandsItsClockToTheAgent(t *testing.T) {
	previousDevice, previousMono := openDevice, newMono
	openDevice = func(string) (peertable.Device, error) { return peertable.NewFake(), nil }
	var reads atomic.Int64
	newMono = func() (func() time.Duration, error) {
		return func() time.Duration { reads.Add(1); return 0 }, nil
	}
	t.Cleanup(func() { openDevice, newMono = previousDevice, previousMono })

	config := Config{Interface: "norn-test0", Trust: filepath.Join(vectors(), "trust.cbor"),
		Log: filepath.Join(vectors(), "served"), RunDir: t.TempDir(), StateDir: t.TempDir()}
	config.SetGossipPort(0, true)
	cycle, _, err := build(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := cycle.Once(); err != nil {
		t.Fatal(err)
	}
	if reads.Load() == 0 {
		t.Error("the agent never read the clock nornd built; it is on its own default")
	}
}
