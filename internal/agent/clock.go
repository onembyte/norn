package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/durable"
)

// clockWriteEvery is how far the estimate must have advanced before the clock
// file is rewritten. A daemon polls several times a second, and a file that
// followed every poll would turn a quiet night into a disk benchmark; a
// minute's precision is nothing against a staleness measured in tens of them.
const clockWriteEvery = time.Minute

// restoreClock reads back this node's estimate of witness-time now from when
// it last ran, and seeds the clock with it (D-071 a).
//
// The clock is the one thing D-069 did not carry across a restart. Seeded by
// the first head to verify in the new process, at age zero, a node that had
// called its view `degraded` for two hours -- or had dropped every peer past
// S_hard -- called the very same head `fresh` again, and a restart is
// something whoever keeps a log stale can also cause.
//
// What is kept is the estimate, not the head's quorum time: the head says when
// witnesses signed it, the estimate says how far this node had watched time
// run since. Seeding from it as an instant observed now is a lower bound on
// now -- it was true when written, and time has not run backwards -- so a
// head's age after the restart is at least what it was at the last write, and
// nothing is called fresher than it was. The bound is weaker by however long
// the node was down, which is the direction a freshness check may be wrong in.
func (a *Agent) restoreClock() {
	for _, dir := range a.stateDirs() {
		raw, err := os.ReadFile(filepath.Join(dir, clockFile))
		if errors.Is(err, fs.ErrNotExist) {
			continue // a first start, or a version that kept no clock
		}
		if err == nil {
			var seconds int64
			body, ok := strings.CutPrefix(string(raw), clockMagic)
			if ok {
				seconds, err = strconv.ParseInt(strings.TrimSuffix(body, "\n"), 10, 64)
			} else {
				err = errors.New("not a norn-clock/v1 file")
			}
			if err == nil {
				kept := time.Unix(seconds, 0)
				a.clock.Observe(kept, a.cfg.Mono())
				a.clockWritten, a.clockWrittenSet = kept, true
				return
			}
		}
		// Guessing a time from a file that does not parse would be worse than
		// having none: the node starts as a first start does, and says so.
		a.emit(Event{Kind: ClockUnusable, Message: fmt.Sprintf(
			"the witness clock kept in %s could not be read (%v); until a head "+
				"verifies this node has no clock, and a view it had called stale may "+
				"not be called so again", dir, err)})
		return
	}
}

// saveClock writes the clock's estimate of now once it has advanced
// clockWriteEvery past the last write, whatever the log is doing: an outage is
// exactly when the file matters, because the estimate keeps advancing while
// nothing verifies, and that advance is what a restart must not lose.
func (a *Agent) saveClock() {
	dir := a.stateDir()
	if dir == "" {
		return
	}
	now, ok := a.clock.EstimatedNow(a.cfg.Mono())
	if !ok || (a.clockWrittenSet && now.Sub(a.clockWritten) < clockWriteEvery) {
		return
	}
	err := os.MkdirAll(dir, 0o755)
	if err == nil {
		err = durable.WriteFile(filepath.Join(dir, clockFile),
			[]byte(clockMagic+strconv.FormatInt(now.Unix(), 10)+"\n"), 0o644)
	}
	if err != nil {
		a.emit(Event{Kind: ClockUnusable, Message: fmt.Sprintf(
			"the witness clock could not be kept in %s (%v); a restart will not "+
				"know how old this view had become", dir, err)})
		return
	}
	a.clockWritten, a.clockWrittenSet = now, true
}
