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
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/onembyte/norn/internal/ed25519v1"
	"github.com/onembyte/norn/internal/note"
)

// ErrPolicy reports a policy that cannot be used.
var ErrPolicy = errors.New("policy error")

func policyErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrPolicy, fmt.Sprintf(format, args...))
}

// NoQuorum is the special name that disables the cosignature requirement.
const NoQuorum = "none"

// maxNameLen bounds a witness or group name, as §9.1 bounds a trust file's
// witness name.
const maxNameLen = 64

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
	if !strings.HasSuffix(text, "\n") {
		return nil, policyErrorf("the final directive must end in a line feed")
	}

	p := &Policy{groups: map[string]group{}, names: map[string]bool{}}
	seenPublicKeys := map[string]bool{}
	quorumLines := 0

	for number, raw := range strings.Split(text, "\n") {
		where := fmt.Sprintf("line %d", number+1)
		// C2SP tlog-policy is a byte format: only tab and line feed are
		// permitted ASCII controls. This check precedes comment handling, so a
		// comment cannot hide a control byte.
		for _, r := range raw {
			if forbiddenControl(r) {
				return nil, policyErrorf("%s: forbidden ASCII control byte", where)
			}
		}
		line := strings.Trim(raw, " \t")
		// Ignored: a line that is empty or holds only spaces and tabs, and a
		// line whose first non-space character is `#`. §9.1 states both,
		// because the reference implementation refused them and this one did
		// not, and nothing in the suite could tell (cold gate run 8, D12).
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := splitFields(line)

		switch fields[0] {
		case "log":
			if len(fields) < 2 || len(fields) > 3 {
				return nil, policyErrorf("%s: log takes a key and an optional url", where)
			}
			v, err := parsePolicyVKey(fields[1], note.AlgEd25519)
			if err != nil {
				return nil, policyErrorf("%s: invalid log verifier key: %v", where, err)
			}
			if seenPublicKeys[string(v.Public)] {
				return nil, policyErrorf("%s: that public key is already in this policy", where)
			}
			seenPublicKeys[string(v.Public)] = true
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
			if name == NoQuorum {
				return nil, policyErrorf("%s: %q is predefined and cannot be a witness name", where, name)
			}
			if !validName(name) {
				return nil, policyErrorf("%s: %q is not a policy name", where, name)
			}
			if p.names[name] {
				return nil, policyErrorf("%s: %q is already defined", where, name)
			}
			v, err := parsePolicyVKey(fields[2], note.AlgCosignature)
			if err != nil {
				return nil, policyErrorf("%s: invalid witness verifier key: %v", where, err)
			}
			if seenPublicKeys[string(v.Public)] {
				return nil, policyErrorf("%s: that public key is already in this policy", where)
			}
			seenPublicKeys[string(v.Public)] = true
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
			if name == NoQuorum {
				return nil, policyErrorf("%s: %q is predefined and cannot be a group name", where, name)
			}
			if !validName(name) {
				return nil, policyErrorf("%s: %q is not a policy name", where, name)
			}
			if p.names[name] {
				return nil, policyErrorf("%s: %q is already defined", where, name)
			}
			seen := map[string]bool{}
			for _, member := range members {
				if member == NoQuorum {
					return nil, policyErrorf("%s: the predefined %q cannot be a group member", where, member)
				}
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
			if fields[1] != NoQuorum && !p.names[fields[1]] {
				return nil, policyErrorf("%s: quorum names %q, which is not defined earlier", where, fields[1])
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
	return p, nil
}

func forbiddenControl(r rune) bool {
	return r < 0x20 && r != '\t' && r != '\n' || r == 0x7f
}

// validName is a witness or group name (D-078, cold gate run 15's M1): §7's
// key-name grammar, at most 64 bytes, the bound a trust file already put on a
// witness name. The grammar never said which bytes a name may hold; both
// implementations took `zürich`, a reader applying the key-name sentence
// refused it, and a refused `policy` entry leaves two readers with different
// quorums.
func validName(name string) bool {
	return len(name) <= maxNameLen && note.ValidKeyName(name)
}

func parsePolicyVKey(text string, wantAlg byte) (note.Verifier, error) {
	v, err := note.ParseVerifierKey(text)
	if err != nil {
		return note.Verifier{}, err
	}
	if v.Alg != wantAlg {
		return note.Verifier{}, fmt.Errorf("verifier key uses algorithm 0x%02x, want 0x%02x", v.Alg, wantAlg)
	}
	// Policy text admits verifier keys into state just as an entry does (D-075).
	if !ed25519v1.ValidPoint(v.Public) {
		return note.Verifier{}, fmt.Errorf("verifier key is not a valid point (SPEC §3.1)")
	}
	return v, nil
}

// splitFields splits on runs of spaces and tabs, and nothing else.
func splitFields(line string) []string {
	return strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
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
	// Canonical decimal, like §6's size line: `02` and `2` are the same number
	// and two spellings of a quorum are two policies that look different and
	// are not (cold gate run 9, D7).
	if keyword != strconv.Itoa(k) {
		return 0, fmt.Errorf("%q is not canonical decimal", keyword)
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

// Label maps the name a cosignature carries back to the short name this policy
// files that witness under. They are two names for one party -- `witness pi
// norn-witness/pi+...` -- and the quorum is evaluated over the short ones, so
// anything holding a cosignature has to cross this boundary.
//
// Quorum callers must use LabelFor to distinguish keys sharing a name.
// A name no witness line claims is returned unchanged: it belongs to somebody
// else's network, and it will not satisfy anything.
func (p *Policy) Label(cosignerName string) string {
	for _, w := range p.Witnesses {
		if v, err := note.ParseVerifierKey(w.Key); err == nil && v.Name == cosignerName {
			return w.Name
		}
	}
	return cosignerName
}

// CollusionBound reports the minimum number of witnesses that must collude
// with the log to cosign two histories under a flat k-of-N quorum:
// max(0, 2k-N). It does not cover quorum none or a quorum naming one witness.
// Nested groups are left to the operator because their overlapping member
// sets cannot be described by a single k and N.
func (p *Policy) CollusionBound() (colluders int, ok bool) {
	g, ok := p.groups[p.quorum]
	if !ok {
		return 0, false
	}
	for _, member := range g.members {
		if _, nested := p.groups[member]; nested {
			return 0, false
		}
	}
	return max(0, g.threshold-(len(g.members)-g.threshold)), true
}

// LabelFor maps a verified cosignature to the short name of its witness.
// Independent witness keys can share a note name, so both the name and the
// public key must match before the cosignature can count toward a quorum.
func (p *Policy) LabelFor(noteName string, public []byte) (string, bool) {
	for _, w := range p.Witnesses {
		if v, err := note.ParseVerifierKey(w.Key); err == nil && v.Name == noteName && bytes.Equal(v.Public, public) {
			return w.Name, true
		}
	}
	return "", false
}
