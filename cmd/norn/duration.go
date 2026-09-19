package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseSpan reads a human expiry like `30d`, `12h` or `90m`.
//
// Go's time.ParseDuration stops at hours, and `ENROLLMENT.md` writes expiries
// in days ("--expires 30d") because that is how people talk about a
// contractor's laptop. Days and weeks are treated as fixed 24-hour and 7-day
// spans: an expiry is a point in the log's timeline, not a calendar date, so
// daylight saving has no opinion about it.
func parseSpan(text string) (time.Duration, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0, fmt.Errorf("empty duration")
	}
	unit := trimmed[len(trimmed)-1]
	if unit == 'd' || unit == 'w' {
		count, err := strconv.ParseFloat(trimmed[:len(trimmed)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("not a duration: %q", text)
		}
		span := 24 * time.Hour
		if unit == 'w' {
			span = 7 * 24 * time.Hour
		}
		if count <= 0 {
			return 0, fmt.Errorf("a duration must be positive: %q", text)
		}
		return time.Duration(count * float64(span)), nil
	}
	span, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("not a duration: %q (try 30d, 12h, 90m)", text)
	}
	if span <= 0 {
		return 0, fmt.Errorf("a duration must be positive: %q", text)
	}
	return span, nil
}

// labels collects repeated -label k=v flags.
type labels map[string]string

func (l labels) String() string { return "" }

func (l labels) Set(value string) error {
	key, text, found := strings.Cut(value, "=")
	if !found || key == "" {
		return fmt.Errorf("a label is key=value, got %q", value)
	}
	if _, repeated := l[key]; repeated {
		return fmt.Errorf("label %q given twice", key)
	}
	l[key] = text
	return nil
}
