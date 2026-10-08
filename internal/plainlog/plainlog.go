// Package plainlog says what a log entry did, in words.
//
// `ENROLLMENT.md` part 7 rule 5 asks `norn status` for "the last five log
// entries in plain words". That is not decoration: an operator who cannot read
// their own log will not notice the entry they did not expect, and an audit
// trail nobody reads is an audit trail that does not work.
//
// Every description says who acted and what changed. Times are prefixed with
// the entry's `ts`, which is the *signer's* clock and advisory (§4.1) -- so the
// caller is expected to label it as such rather than present it as fact.
package plainlog

import (
	"fmt"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
)

// Describe renders one entry as a sentence.
func Describe(env *entry.Envelope) string {
	who := actors(env)
	switch env.T {
	case "genesis":
		return fmt.Sprintf("%s created the network %q with %d root(s) and %d signer(s)",
			who, text(env.Body, "name"), count(env.Body, "roots"), count(env.Body, "signers"))
	case "enroll":
		device, wg := enrolled(env)
		return fmt.Sprintf("%s enrolled %s (wireguard %s)", who, device, wg)
	case "rotate":
		if _, ok := env.Body["device_pk"]; ok {
			return fmt.Sprintf("%s rotated %s's WireGuard and identity keys",
				who, text(env.Body, "device_id"))
		}
		return fmt.Sprintf("%s rotated %s's WireGuard key", who, text(env.Body, "device_id"))
	case "revoke":
		if reason := text(env.Body, "reason"); reason != "" {
			return fmt.Sprintf("%s revoked %s (%s)", who, text(env.Body, "device_id"), reason)
		}
		return fmt.Sprintf("%s revoked %s", who, text(env.Body, "device_id"))
	case "signer_add":
		return fmt.Sprintf("%s added signer %s", who, kidOf(env.Body, "pk"))
	case "signer_remove":
		return fmt.Sprintf("%s removed signer %s", who, text(env.Body, "kid"))
	case "root_add":
		return fmt.Sprintf("%s added root %s", who, kidOf(env.Body, "pk"))
	case "root_remove":
		return fmt.Sprintf("%s removed root %s", who, text(env.Body, "kid"))
	case "signer_thr":
		return fmt.Sprintf("%s set the signer threshold to %d", who, number(env.Body, "thr"))
	case "root_thr":
		return fmt.Sprintf("%s set the root threshold to %d", who, number(env.Body, "thr"))
	case "params":
		return fmt.Sprintf("%s changed %s", who, changedParams(env.Body))
	case "policy":
		return fmt.Sprintf("%s replaced the witness policy", who)
	case "log_key":
		return fmt.Sprintf("%s rotated the log key, with a %s overlap",
			who, span(number(env.Body, "overlap")))
	case "note":
		return fmt.Sprintf("%s noted: %q", who, text(env.Body, "text"))
	default:
		// Not reachable for a decoded entry -- `t` is closed (§4.3) -- but a
		// new type must not silently print as nothing.
		return fmt.Sprintf("%s made a %s entry", who, env.T)
	}
}

// DescribeRejected renders what an entry would have done if replay accepted it.
func DescribeRejected(env *entry.Envelope) string {
	who := actors(env)
	return who + " would have " + strings.TrimPrefix(Describe(env), who+" ")
}

// Ago renders how long before `now` the entry claims to have been signed.
func Ago(env *entry.Envelope, now time.Time) string {
	d := now.Sub(time.Unix(int64(env.TS), 0))
	switch {
	case d < 0:
		return "in the future"
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// actors names who signed, by role and kid. Names are not available: the log
// binds keys, not people, and inventing a display name here would put a
// friendly label on a key nobody vouched for.
func actors(env *entry.Envelope) string {
	if len(env.Sigs) == 0 {
		return "nobody"
	}
	roles := map[string][]string{}
	order := []string{}
	for _, sig := range env.Sigs {
		if _, seen := roles[sig.Role]; !seen {
			order = append(order, sig.Role)
		}
		roles[sig.Role] = append(roles[sig.Role], short(sig.Kid))
	}
	parts := make([]string, 0, len(order))
	for _, role := range order {
		kids := roles[role]
		label := role
		if len(kids) > 1 {
			label = role + "s"
		}
		parts = append(parts, fmt.Sprintf("%s %s", label, strings.Join(kids, " and ")))
	}
	return strings.Join(parts, " with ")
}

// enrolled reads the device the entry enrols out of its embedded request
// (§4.3): the body carries the device's own words, not a restatement.
func enrolled(env *entry.Envelope) (device, wg string) {
	raw, ok := env.Body["request"].([]byte)
	if !ok {
		return "an unreadable request", "?"
	}
	request, err := enrollreq.Decode(raw)
	if err != nil {
		return "an unreadable request", "?"
	}
	return request.DeviceID, short(fmt.Sprintf("%x", request.WGPK))
}

func changedParams(body map[string]any) string {
	keys := make([]string, 0, len(body))
	for key := range body {
		keys = append(keys, key)
	}
	sortStrings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s to %v", key, body[key]))
	}
	if len(parts) == 0 {
		return "no parameters"
	}
	return strings.Join(parts, ", ")
}

func span(seconds uint64) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d-day", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%d-hour", int(d.Hours()))
	default:
		return fmt.Sprintf("%d-second", seconds)
	}
}

func text(body map[string]any, key string) string {
	s, _ := body[key].(string)
	return s
}

func number(body map[string]any, key string) uint64 {
	n, _ := body[key].(uint64)
	return n
}

func count(body map[string]any, key string) int {
	items, _ := body[key].([]any)
	return len(items)
}

func kidOf(body map[string]any, key string) string {
	raw, ok := body[key].([]byte)
	if !ok {
		return "?"
	}
	return short(entry.Kid(raw))
}

// short trims an identifier to something a person can compare on a screen
// without losing the ability to tell two apart at a glance.
func short(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
