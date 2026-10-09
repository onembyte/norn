// These vectors write the served-twice-cosigned directory.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
)

// writeTwiceCosignedHead ships §5.3's tie-break: one witness, two verifying
// cosignature lines, at different times.
//
// Cold gate run 8, D5... D13: §5.3 says "two verifying lines from the same
// witness with different timestamps are its newest", and nothing in the suite
// had two lines from one witness that BOTH verify.
// `checkpoints-bad/12-second-line-from-one-witness` cannot stand in: its
// second line does not verify, so §10's per-line rule refuses the checkpoint
// before the tie-break is reached. `quorum-time-oldest-line` -- a reader that
// reduces each witness to its OLDEST line -- passed all 582 checks.
//
// `pi` answers again three spreads out, so the two readings give different
// answers: newest-per-witness puts pi ahead of both others and the 2-of-3
// instant lands on `friend`; oldest-per-witness leaves pi at the back and it
// lands on `vps`. Every line here verifies, so the checkpoint is valid and the
// only question is which instant it vouches for.
func writeTwiceCosignedHead(root, signed string, signers []cosignpkg.Signer) error {
	if len(signers) < 3 {
		return fmt.Errorf("the fixture has %d witnesses; this case needs three", len(signers))
	}
	again := time.Unix(CosignedAt+int64(3*CosignSpread), 0)
	head, err := cosignpkg.Append([]cosignpkg.Signer{signers[0]}, cosignpkg.At(again))(signed)
	if err != nil {
		return err
	}

	dir := filepath.Join(root, "served-twice-cosigned")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(head), 0o644); err != nil {
		return err
	}
	meta := map[string]any{
		"serve_over":   "served",
		"signs_twice":  signers[0].Name,
		"quorum_time":  CosignedAt + int64(2*CosignSpread),
		"oldest_would": CosignedAt + int64(CosignSpread),
		"comment": "the served head with a FOURTH cosignature line: " +
			signers[0].Name + " answers a second time, later, and both of its lines " +
			"verify. SPEC 5.3 says a witness counts once, at its newest, so this head " +
			"MUST be accepted and its evaluation time is `quorum_time`. A reader that " +
			"takes each witness's oldest line instead gets `oldest_would`, which is " +
			"the reading this case exists to rule out. Serve it in place of " +
			"served/checkpoint over the same tiles",
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(blob, '\n'), 0o644)
}
