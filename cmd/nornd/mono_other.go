//go:build !linux

package main

import "time"

// monotonic is Go's monotonic reading, from zero when nornd starts. It does
// not count a suspend on the platforms nornd runs on outside Linux (see clock).
func monotonic() (func() time.Duration, error) {
	return sinceStart(), nil
}
