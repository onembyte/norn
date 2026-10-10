package monitor

import (
	"fmt"
	"sort"
	"time"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/receipt"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/trust"
)

// Inbox holds the receipts submitters have forwarded to the monitor, and
// notices when the log has broken one.
//
// SPEC §7, quoted because every decision here follows from it: *"A receipt
// whose leaf is absent from every checkpoint **cosigned after `deadline`** is
// non-repudiable proof of log misbehaviour."*
//
// **Cosigned after.** The comparison is against witness time, not the
// monitor's clock. That is what makes the finding non-repudiable rather than
// an accusation: it does not depend on the accuser's clock being right, and a
// monitor running fast cannot slander an honest log. It also means a witness
// outage produces silence rather than a false alarm, because with no
// cosignature nothing can be said to be late.
type Inbox struct {
	// held is every receipt still waiting to be included, keyed by leaf hash.
	held map[string]*receipt.Receipt
}

// NewInbox builds an empty inbox.
func NewInbox() *Inbox { return &Inbox{held: map[string]*receipt.Receipt{}} }

// Add takes a receipt a submitter forwarded.
//
// Anybody can forward one, so anybody could forward a forgery: it is checked
// at the door against this network's origin and the log keys the monitor
// trusts -- the trust file's, plus `learned`, the keys a state it verified
// published (§7, §9.4, D-074 (a)). A receipt that is not
// this log's word is not evidence of anything, and keeping it would mean the
// monitor could be made to accuse an honest operator by anyone who can reach
// it.
func (i *Inbox) Add(signed string, anchor *trust.Trust, learned []string) error {
	// No leaf to bind against -- the monitor is not the submitter -- and no
	// deadline judgement here: that is Check's, against witness time.
	keys := append([]string{anchor.LogKey}, learned...)
	parsed, err := receipt.Check(signed, keys, anchor.Origin, nil,
		time.Time{})
	if err != nil {
		return err
	}
	i.held[string(parsed.LeafHash)] = parsed
	return nil
}

// Pending is how many receipts are still waiting.
func (i *Inbox) Pending() int { return len(i.held) }

// Check reports every receipt the log has now broken, and forgets the ones it
// has honoured.
//
// A proven misbehaviour stays pending on purpose. The proof does not stop
// being true because it has been mentioned once, and an operator who was
// asleep still has to find it in the morning.
func (i *Inbox) Check(result *logclient.Result, rules Rules) []Alert {
	included := map[string]bool{}
	for _, raw := range result.Served {
		leaf := tlog.LeafHash(raw)
		included[string(leaf[:])] = true
	}

	// Honoured receipts are finished with.
	for key := range i.held {
		if included[key] {
			delete(i.held, key)
		}
	}
	if result.QuorumTime == nil {
		// No witness time, so no deadline has demonstrably passed.
		return nil
	}

	var late []*receipt.Receipt
	for _, held := range i.held {
		if result.QuorumTime.After(held.DeadlineTime()) {
			late = append(late, held)
		}
	}
	sort.Slice(late, func(a, b int) bool { return late[a].Deadline < late[b].Deadline })

	alerts := make([]Alert, 0, len(late))
	for _, held := range late {
		alerts = append(alerts, Alert{
			Rule: "receipt-deadline", Level: Critical,
			Subject: fmt.Sprintf("%x", held.LeafHash[:8]),
			Message: fmt.Sprintf("the log promised entry %x… would be included by %s "+
				"and it is in no checkpoint. The witnesses have cosigned a head at %s, "+
				"which is later, so this is not a delay -- the receipt is signed by "+
				"the log's own key and is proof it broke its word (§7).",
				held.LeafHash[:8], held.DeadlineTime().UTC().Format(time.RFC3339),
				result.QuorumTime.UTC().Format(time.RFC3339))})
	}
	return alerts
}
