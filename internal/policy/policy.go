// Package policy reads `c2sp.org/tlog-policy`: who must cosign a checkpoint
// before a node will believe it.
//
// `GOSSIP.md` part 1: witnesses guard against the log. The policy is where a
// network writes down how much of that guard it wants — "two of pi, vps and
// friend" — and `norn.trust` carries it verbatim, with no Norn dialect.
//
// The grammar here is the published one, checked against the specification
// rather than against the shape this project happened to invent in Phase 0.
// That distinction is not academic: 4.1a found a key encoding that was wrong
// in exactly the way an unverified guess is wrong.
package policy

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrPolicy reports a policy that cannot be used.
var ErrPolicy = errors.New("policy error")

func policyErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrPolicy, fmt.Sprintf(format, args...))
}

// NoQuorum is the special name that disables the cosignature requirement.
const NoQuorum = "none"

// Witness is one cosigner the policy names.
type Witness struct {
	Name string
	Key  string
	URL  string
}

// Log is the log the policy is about.
type Log struct {
	Key string
	URL string
}

// group is a named threshold over witnesses and other groups.
type group struct {
	name      string
	threshold int
	members   []string
}

// Policy is a parsed policy file.
type Policy struct {
	Logs      []Log
	Witnesses []Witness
	quorum    string
	groups    map[string]group
	// order preserves the file's own ordering, which the error messages use.
	names map[string]bool
}

// Quorum is the name the quorum line points at.
func (p *Policy) Quorum() string { return p.quorum }

// RequiresCosignatures reports whether this policy asks for any at all.
func (p *Policy) RequiresCosignatures() bool { return p.quorum != NoQuorum }

// Parse reads a policy file.
//
// It is strict on purpose. A policy is the one place a network says how much
// independent corroboration it wants, and a line nobody understood is a
// requirement nobody is enforcing — so an unknown keyword, a forward
// reference or a threshold larger than its group is an error, not a warning.
func Parse(text string) (*Policy, error) {
	p := &Policy{groups: map[string]group{}, names: map[string]bool{}}
	seenKeys := map[string]bool{}
	quorumLines := 0

	for number, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		where := fmt.Sprintf("line %d", number+1)

		switch fields[0] {
		case "log":
			if len(fields) < 2 || len(fields) > 3 {
				return nil, policyErrorf("%s: log takes a key and an optional url", where)
			}
			if seenKeys[fields[1]] {
				return nil, policyErrorf("%s: that key is already in this policy", where)
			}
			seenKeys[fields[1]] = true
			entry := Log{Key: fields[1]}
			if len(fields) == 3 {
				entry.URL = fields[2]
			}
			p.Logs = append(p.Logs, entry)

		case "witness":
			if len(fields) < 3 || len(fields) > 4 {
				return nil, policyErrorf("%s: witness takes a name, a key and an optional url", where)
			}
			name := fields[1]
			if p.names[name] {
				return nil, policyErrorf("%s: %q is already defined", where, name)
			}
			if seenKeys[fields[2]] {
				return nil, policyErrorf("%s: that key is already in this policy", where)
			}
			seenKeys[fields[2]] = true
			p.names[name] = true
			entry := Witness{Name: name, Key: fields[2]}
			if len(fields) == 4 {
				entry.URL = fields[3]
			}
			p.Witnesses = append(p.Witnesses, entry)

		case "group":
			if len(fields) < 4 {
				return nil, policyErrorf("%s: group takes a name, a threshold and members", where)
			}
			name, keyword, members := fields[1], fields[2], fields[3:]
			if p.names[name] {
				return nil, policyErrorf("%s: %q is already defined", where, name)
			}
			seen := map[string]bool{}
			for _, member := range members {
				// Members must already exist: a policy that referred forward
				// could describe a cycle, and a cycle has no meaning here.
				if !p.names[member] {
					return nil, policyErrorf("%s: %q is not defined yet", where, member)
				}
				if seen[member] {
					return nil, policyErrorf("%s: %q appears twice in one group", where, member)
				}
				seen[member] = true
			}
			threshold, err := parseThreshold(keyword, len(members))
			if err != nil {
				return nil, policyErrorf("%s: %v", where, err)
			}
			p.names[name] = true
			p.groups[name] = group{name: name, threshold: threshold, members: members}

		case "quorum":
			if len(fields) != 2 {
				return nil, policyErrorf("%s: quorum takes one name", where)
			}
			quorumLines++
			p.quorum = fields[1]

		default:
			return nil, policyErrorf("%s: %q is not a policy keyword", where, fields[0])
		}
	}

	if quorumLines != 1 {
		return nil, policyErrorf("a policy has exactly one quorum line, this one has %d", quorumLines)
	}
	if p.quorum != NoQuorum && !p.names[p.quorum] {
		return nil, policyErrorf("the quorum names %q, which nothing defines", p.quorum)
	}
	return p, nil
}

// parseThreshold reads `all`, `any` or a number.
func parseThreshold(keyword string, members int) (int, error) {
	switch keyword {
	case "all":
		return members, nil
	case "any":
		return 1, nil
	}
	k, err := strconv.Atoi(keyword)
	if err != nil {
		return 0, fmt.Errorf("%q is not all, any or a number", keyword)
	}
	if k < 1 || k > members {
		return 0, fmt.Errorf("a threshold of %d over %d member(s) can never be met", k, members)
	}
	return k, nil
}

// Satisfied reports whether these cosigners meet the quorum.
//
// Names, not keys: a caller has already checked the signatures, and what is
// left is a question about *who*. Anyone the policy does not name counts for
// nothing, however valid their signature.
func (p *Policy) Satisfied(cosigners []string) bool {
	have := make(map[string]bool, len(cosigners))
	for _, name := range cosigners {
		have[name] = true
	}
	if p.quorum == NoQuorum {
		return true
	}
	return p.satisfies(p.quorum, have, map[string]bool{})
}

func (p *Policy) satisfies(name string, have map[string]bool, visiting map[string]bool) bool {
	if g, ok := p.groups[name]; ok {
		if visiting[name] {
			return false // unreachable: forward references are refused at parse
		}
		visiting[name] = true
		defer delete(visiting, name)

		met := 0
		for _, member := range g.members {
			if p.satisfies(member, have, visiting) {
				met++
			}
		}
		return met >= g.threshold
	}
	return have[name]
}

// WitnessNames lists the witnesses the policy names, in order.
func (p *Policy) WitnessNames() []string {
	out := make([]string, 0, len(p.Witnesses))
	for _, w := range p.Witnesses {
		out = append(out, w.Name)
	}
	return out
}

// Keys returns the witness verifier keys, for checking cosignatures.
func (p *Policy) Keys() []string {
	out := make([]string, 0, len(p.Witnesses))
	for _, w := range p.Witnesses {
		out = append(out, w.Key)
	}
	sort.Strings(out)
	return out
}
