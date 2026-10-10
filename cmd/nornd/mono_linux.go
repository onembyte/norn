//go:build linux

package main

import (
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// bootTimeID and x/sys/unix's CLOCK_BOOTTIME are one number: each array
// length below is a constant that must not be negative, so this file builds
// only while they are equal.
var (
	_ [unix.CLOCK_BOOTTIME - bootTimeID]struct{}
	_ [bootTimeID - unix.CLOCK_BOOTTIME]struct{}
)

// monotonic reads CLOCK_BOOTTIME, from zero when nornd starts. A reading the
// kernel refuses after the first -- it does not, for this clock -- repeats the
// last one rather than mixing in another clock: the reading may stall, and it
// never runs backwards.
func monotonic() (func() time.Duration, error) {
	id := clockFor("linux").id
	var start unix.Timespec
	if err := unix.ClockGettime(id, &start); err != nil {
		return nil, err
	}
	var last atomic.Int64
	return func() time.Duration {
		var now unix.Timespec
		if err := unix.ClockGettime(id, &now); err != nil {
			return time.Duration(last.Load())
		}
		elapsed := now.Nano() - start.Nano()
		last.Store(elapsed)
		return time.Duration(elapsed)
	}, nil
}
