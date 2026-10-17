package main

// clock names the monotonic clock nornd's reading comes from (§15's
// "monotonic time since").
//
// The age of a view is witness time plus monotonic time since it was learned,
// so a reading that stops while the machine is suspended makes a node that
// slept for an hour believe its view is an hour younger than it is. Linux has
// a clock that keeps counting through a suspend, CLOCK_BOOTTIME, and nornd
// reads it there. Elsewhere it uses Go's monotonic reading, which on the
// platforms nornd runs on today does not count a suspend: that is the gap
// D-074 (b)'s review named, stated here rather than hidden.
type clock struct {
	name string
	id   int32
}

const (
	goMonotonic = "Go's monotonic reading"
	noClockID   = -1
	// bootTimeID is Linux's CLOCK_BOOTTIME. It is restated rather than taken
	// from x/sys/unix so the choice can be tested on any platform; the Linux
	// build checks the two agree, so they cannot drift.
	bootTimeID = 7
)

// clockFor is the clock nornd reads on goos.
func clockFor(goos string) clock {
	if goos == "linux" {
		return clock{"CLOCK_BOOTTIME", bootTimeID}
	}
	return clock{goMonotonic, noClockID}
}

// newMono is the monotonic reading build hands the agent; a variable so a
// test can see that it does.
var newMono = monotonic
