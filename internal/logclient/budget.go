package logclient

import "time"

// Budgeted bounds one verification, start to finish.
//
// Each request to a log has a deadline (Timeout), but one verification is a
// request per entry bundle and hash tile, and a log that answers each of them
// just slowly enough holds the verifier for as long as it has files -- a stall
// no per-request bound can see (HARDENING-PLAN H2-c, review F2). The wrapper
// refuses further requests once the budget is spent; the verification then
// fails as any other does, and the node reconciles on what last verified.
//
// It is a Fetcher, so nothing between the verifier and the log changes:
// `Verify` neither knows nor needs to know that its source will say no.
func Budgeted(f Fetcher, budget time.Duration) Fetcher {
	return budgeted{Fetcher: f, deadline: time.Now().Add(budget), budget: budget}
}

type budgeted struct {
	Fetcher
	deadline time.Time
	budget   time.Duration
}

func (b budgeted) Fetch(path string) ([]byte, error) {
	if time.Now().After(b.deadline) {
		return nil, logErrorf("not fetching %s: this verification's %s budget is spent", path, b.budget)
	}
	return b.Fetcher.Fetch(path)
}
