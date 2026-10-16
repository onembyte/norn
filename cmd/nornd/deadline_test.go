package main

import (
	"testing"
	"time"
)

// Two seconds at least, so a quiet machine keeps the old bound; four times
// the unstalled cycle plus a second otherwise, so a loaded one is not held to
// a number chosen on a quiet day.
func TestAWatchDeadlineScalesWithTheMachine(t *testing.T) {
	for _, c := range []struct{ unstalled, want time.Duration }{
		{0, 2 * time.Second},
		{200 * time.Millisecond, 2 * time.Second},
		{time.Second, 5 * time.Second},
		{3 * time.Second, 13 * time.Second},
	} {
		if got := scaledDeadline(c.unstalled); got != c.want {
			t.Errorf("scaledDeadline(%v) = %v, want %v", c.unstalled, got, c.want)
		}
	}
}
