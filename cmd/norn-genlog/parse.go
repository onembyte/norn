package main

import "strings"

func splitLines(s string) []string { return strings.Split(s, "\n") }

func cutPrefix(line, key string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, key) {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(trimmed, key))
	if !strings.HasPrefix(rest, "=") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(rest, "=")), true
}

func trimQuoted(s string) string {
	if i := strings.Index(s, "#"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return strings.Trim(s, `"`)
}
