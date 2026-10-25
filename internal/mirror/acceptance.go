package mirror

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/tlog"
)

// Acceptance is what a node remembers about accepting one tree head, apart
// from the policy its entries publish for the next head (D-082 (1)).
type Acceptance struct {
	Policy     string
	QuorumTime *time.Time
}

// acceptanceRecord uses JSON for local metadata, like the node's clock file:
// a version, the exact tree identity, verbatim policy text and Unix seconds.
// Null is an explicit absence of witness time, as it is in proven.json.
// The checkpoint is still verified; this file never replaces its evidence.
type acceptanceRecord struct {
	Version    int    `json:"version"`
	Head       string `json:"head"`
	Policy     string `json:"policy"`
	QuorumTime *int64 `json:"quorum_time"`
}

// Name each record by the tree head, not the note's signature lines. Keeping
// prior records makes a crash before the checkpoint rename harmless: the old
// checkpoint still finds its own acceptance. A single overwritten sidecar
// would instead apply the new policy and time to the old checkpoint.
func acceptanceName(cp tlog.Checkpoint) string {
	return fmt.Sprintf("acceptance-%x.json", sha256.Sum256([]byte(cp.Marshal())))
}

// WriteAccepted writes a node's mirror with the policy and time that accepted
// it. The acceptance record is durable before Write publishes the checkpoint,
// including when an old mirror with no record is upgraded in place.
func WriteAccepted(dir string, cp tlog.Checkpoint, signed string, entries [][]byte, acceptance Acceptance) error {
	return writeMirror(dir, cp, signed, entries, &acceptance)
}

func writeAcceptance(dir string, cp tlog.Checkpoint, acceptance Acceptance) error {
	record := acceptanceRecord{Version: 1, Head: cp.Marshal(), Policy: acceptance.Policy}
	if acceptance.QuorumTime != nil {
		at := acceptance.QuorumTime.Unix()
		record.QuorumTime = &at
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return write(dir, acceptanceName(cp), append(raw, '\n'))
}

// pruneAcceptance removes every acceptance record but keep's. A node writes one
// per head it accepts, a minute apart on a small network, and once a head is
// published no other record is read again. Only the exact spelling
// acceptanceName produces is removed: the directory can hold operator files.
func pruneAcceptance(dir, keep string) error {
	names, err := filepath.Glob(filepath.Join(dir, "acceptance-*.json"))
	if err != nil {
		return err
	}
	for _, path := range names {
		name := filepath.Base(path)
		digest, ok := strings.CutSuffix(strings.TrimPrefix(name, "acceptance-"), ".json")
		if name == keep || !ok || len(digest) != 2*sha256.Size || strings.Trim(digest, "0123456789abcdef") != "" {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// ReadAcceptance returns nil only for an older mirror with no record for this
// head. An unreadable, malformed or misbound record is an unusable mirror,
// never a reason to retry under a different policy.
func ReadAcceptance(dir string, cp tlog.Checkpoint) (*Acceptance, error) {
	raw, err := os.ReadFile(filepath.Join(dir, acceptanceName(cp)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record acceptanceRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, mirrorErrorf("reading acceptance: %v", err)
	}
	if record.Version != 1 || record.Head != cp.Marshal() || record.Policy == "" ||
		(record.QuorumTime != nil && *record.QuorumTime < 0) {
		return nil, mirrorErrorf("invalid acceptance for the mirrored head")
	}
	acceptance := &Acceptance{Policy: record.Policy}
	if record.QuorumTime != nil {
		at := time.Unix(*record.QuorumTime, 0)
		acceptance.QuorumTime = &at
	}
	return acceptance, nil
}
