// Package witness speaks `c2sp.org/tlog-witness` to a witness: it submits a
// checkpoint and brings back the cosignatures.
//
// This is the other half of the argument the whole project rests on. A log can
// sign anything it likes, including two different histories for two different
// nodes; what it cannot do is get independent witnesses to cosign both at the
// same size (`GOSSIP.md` part 1). Until a log can actually ask them, every
// checkpoint it serves is its own word for itself.
//
// The protocol was fetched rather than recalled. That habit found the
// algorithm-byte defect in 4.1a, where the shipped code could not have
// accepted a real witness at all.
package witness

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
)

// ErrWitness reports a witness that would not cosign.
var ErrWitness = errors.New("witness error")

func witnessErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrWitness, fmt.Sprintf(format, args...))
}

// ConflictError is the one refusal that carries data: the witness has already
// cosigned a different size, and says which. A log that dropped this would
// retry the same rejected request forever, so it is a typed error rather than
// a message.
type ConflictError struct {
	// WitnessSize is the tree size of the latest checkpoint this witness
	// cosigned. The next attempt proves consistency from here.
	WitnessSize int64
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%s: the witness last cosigned size %d, so this submission "+
		"did not start where it left off", ErrWitness, e.WitnessSize)
}

func (e *ConflictError) Unwrap() error { return ErrWitness }

// Client is one witness endpoint.
type Client struct {
	// Name is how this network refers to the witness, for messages.
	Name string
	// URL is the submission prefix; `/add-checkpoint` is appended.
	URL string
	// Key is the witness's cosignature verifier key. A line signed by anything
	// else is not this witness answering.
	Key string
	// AlsoTrust are further keys this witness is allowed to answer with: the
	// protocol permits a witness to hold several and return a line for each.
	AlsoTrust []string
	// HTTP is the transport; nil means a client with Timeout.
	HTTP *http.Client
	// Timeout applies when HTTP is nil.
	Timeout time.Duration
}

// DefaultTimeout bounds a submission. A witness that has not answered by then
// is one the log should carry on without rather than stall behind.
const DefaultTimeout = 10 * time.Second

// Add submits `signed` to the witness and returns the cosignature lines it
// returned, each already verified against this witness's keys.
//
// `old` is the tree size the consistency proof starts from, and `proof` is the
// RFC 6962 consistency proof from `old` to the checkpoint's size. The proof
// MUST be empty when `old` is zero.
func (c *Client) Add(signed string, old int64, proof [][]byte) ([]string, error) {
	body, err := c.request(signed, old, proof)
	if err != nil {
		return nil, err
	}

	resp, err := c.client().Post(strings.TrimSuffix(c.URL, "/")+"/add-checkpoint",
		"text/plain; charset=utf-8", strings.NewReader(body))
	if err != nil {
		return nil, witnessErrorf("%s is unreachable: %v", c.name(), err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, witnessErrorf("reading %s's answer: %v", c.name(), err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.refusal(resp.StatusCode, raw)
	}
	return c.check(signed, string(raw))
}

// maxResponse bounds what a witness can make this process hold. A handful of
// signature lines is a few hundred bytes.
const maxResponse = 1 << 16

// request builds the body: the old size, the proof, an empty line, and the
// checkpoint exactly as the log published it.
func (c *Client) request(signed string, old int64, proof [][]byte) (string, error) {
	if old < 0 {
		return "", witnessErrorf("an old size cannot be negative, got %d", old)
	}
	if old == 0 && len(proof) > 0 {
		return "", witnessErrorf("a submission from size zero must carry no consistency " +
			"proof; there is no earlier tree to be consistent with")
	}
	// A proof is required between two *different* sizes. From a size to
	// itself it is empty and correct -- which is what resubmitting a head the
	// witness has already cosigned looks like -- so the rule is keyed on the
	// checkpoint's own size rather than on `old` being non-zero.
	size, err := checkpointSize(signed)
	if err != nil {
		return "", err
	}
	if old > size {
		return "", witnessErrorf("cannot prove consistency from size %d to the smaller "+
			"size %d this checkpoint claims", old, size)
	}
	if old > 0 && old < size && len(proof) == 0 {
		return "", witnessErrorf("a submission from size %d to %d needs a consistency "+
			"proof; without one the witness cannot check we did not rewrite history",
			old, size)
	}
	// "Zero to 63" -- the proof for any tree this side of 2^63 entries.
	if len(proof) > maxProof {
		return "", witnessErrorf("a consistency proof is at most %d hashes, got %d",
			maxProof, len(proof))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "old %d\n", old)
	for _, hash := range proof {
		b.WriteString(base64.StdEncoding.EncodeToString(hash))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(signed)
	return b.String(), nil
}

const maxProof = 63

// checkpointSize reads the size line of a `tlog-checkpoint` note: origin,
// size, root hash.
func checkpointSize(signed string) (int64, error) {
	body, _, err := note.Split(signed)
	if err != nil {
		return 0, witnessErrorf("the checkpoint does not parse: %v", err)
	}
	lines := strings.Split(body, "\n")
	if len(lines) < 3 {
		return 0, witnessErrorf("a checkpoint is origin, size and root; got %d lines",
			len(lines))
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 0 {
		return 0, witnessErrorf("%q is not a tree size", truncate(lines[1]))
	}
	return size, nil
}

// refusal turns a status into something an operator can act on. They are
// different problems with different fixes, so they are not collapsed into
// "the witness said no".
func (c *Client) refusal(status int, raw []byte) error {
	switch status {
	case http.StatusNotFound:
		return witnessErrorf("%s does not know this log's origin; it has not been "+
			"configured to witness this network", c.name())
	case http.StatusForbidden:
		return witnessErrorf("%s does not trust the key this checkpoint is signed "+
			"with; it is configured for a different log key", c.name())
	case http.StatusBadRequest:
		return witnessErrorf("%s says the submitted checkpoint is older than the size "+
			"we claimed to start from, which is this log's own bug", c.name())
	case http.StatusConflict:
		size, err := parseSize(raw)
		if err != nil {
			return witnessErrorf("%s refused with a conflict but its body is not a tree "+
				"size (%v); retrying would be guessing", c.name(), err)
		}
		return &ConflictError{WitnessSize: size}
	case http.StatusUnprocessableEntity:
		return witnessErrorf("%s could not verify consistency from what it holds to what "+
			"we sent. Either this log built the proof wrongly, or it has forked and the "+
			"witness is holding the other branch -- which is the case worth checking "+
			"first", c.name())
	default:
		return witnessErrorf("%s answered %d %s", c.name(), status, http.StatusText(status))
	}
}

// parseSize reads the `text/x.tlog.size` body of a 409.
func parseSize(raw []byte) (int64, error) {
	text := strings.TrimSuffix(string(raw), "\n")
	size, err := strconv.ParseInt(text, 10, 64)
	if err != nil || size < 0 {
		return 0, fmt.Errorf("%q is not a tree size", truncate(text))
	}
	return size, nil
}

func truncate(text string) string {
	if len(text) > 40 {
		return text[:40] + "…"
	}
	return text
}

// check verifies every returned line against this witness's keys, over the
// checkpoint that was actually submitted.
//
// The protocol does not require a submitter to do this, and a log that skipped
// it would publish whatever came back -- a head every verifier then refuses,
// with nothing on the log side to say why. Checking here means a witness
// answering about some other checkpoint, or a middlebox rewriting one, is
// caught where it can still be reported.
func (c *Client) check(signed, answer string) ([]string, error) {
	lines := make([]string, 0, 2)
	for _, line := range strings.Split(strings.TrimRight(answer, "\n"), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return nil, witnessErrorf("%s answered with no cosignature at all", c.name())
	}

	keys := append([]string{c.Key}, c.AlsoTrust...)
	cosignatures, err := cosign.Verify(signed+strings.Join(lines, "\n")+"\n", keys)
	if err != nil {
		return nil, witnessErrorf("%s's answer does not verify over the checkpoint we "+
			"submitted: %v", c.name(), err)
	}
	if len(cosignatures) != len(lines) {
		return nil, witnessErrorf("%s returned %d lines but only %d are cosignatures by "+
			"keys this network attributes to it", c.name(), len(lines), len(cosignatures))
	}
	return lines, nil
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &http.Client{Timeout: timeout}
}

func (c *Client) name() string {
	if c.Name != "" {
		return "witness " + c.Name
	}
	return "the witness"
}
