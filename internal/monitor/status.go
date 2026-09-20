package monitor

import (
	"encoding/hex"
	"html/template"
	"net/http"
	"sort"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/plainlog"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/trust"
)

// Status is the read-only page a monitor serves on the tunnel address
// (`LAB.md` §3): "the Norn equivalent of a CT log's public page — and the
// thing you screenshot for the README."
//
// It is rendered with `html/template`, and that is not a default choice. A
// device's labels are picked by whoever enrolled it, and an alert's text
// carries names a log operator or a peer chose. A page that let either become
// markup would be a network where enrolling a device is enough to rewrite what
// everybody reads.
type Status struct {
	Network *trust.Trust
	// Result is the last verification. Nil before the first one succeeds,
	// which the page says rather than serving a blank screen -- a blank screen
	// is indistinguishable from a broken one.
	Result *logclient.Result
	Alerts []Alert
	// Recent is how many entries to show; zero means DefaultRecent.
	Recent int
	Now    func() time.Time
}

// DefaultRecent is §3's "last 20 entries".
const DefaultRecent = 20

// Handler serves the page. Read-only, like every other surface Norn exposes on
// the tunnel: a status page answers questions and takes no instructions.
func (s *Status) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "a status page takes no instructions", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := statusTemplate.Execute(w, s.view()); err != nil {
			// The headers are already out, so there is nothing useful left to
			// say to the client.
			return
		}
	})
}

// statusView is what the template renders, prepared so the template contains
// no logic worth testing separately.
type statusView struct {
	Name, Origin, Fingerprint string
	Verified                  bool
	Size                      int64
	Root                      string
	Age                       string
	CosignedAt                string
	Witnesses                 []witnessView
	Devices                   []deviceView
	Recent                    []recentView
	Alerts                    []Alert
}

type witnessView struct{ Name, CosignedAt string }

type deviceView struct {
	ID, Key, Proof, Expires string
	Labels                  []labelView
}

type labelView struct{ Key, Value string }

type recentView struct {
	Index int64
	Words string
}

func (s *Status) view() statusView {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	view := statusView{}
	if s.Network != nil {
		view.Name, view.Origin = s.Network.Name, s.Network.Origin
		view.Fingerprint, _ = s.Network.Fingerprint()
	}
	view.Alerts = s.Alerts
	if s.Result == nil {
		return view
	}

	view.Verified = true
	view.Size = s.Result.Checkpoint.Size
	view.Root = hex.EncodeToString(s.Result.Checkpoint.Root[:])
	if s.Result.QuorumTime != nil {
		view.CosignedAt = s.Result.QuorumTime.UTC().Format(time.RFC3339)
		view.Age = now().Sub(*s.Result.QuorumTime).Round(time.Second).String()
	}
	for _, c := range s.Result.Cosignatures {
		view.Witnesses = append(view.Witnesses, witnessView{
			Name: c.Name, CosignedAt: c.Time.UTC().Format(time.RFC3339)})
	}

	// The device table, judged at the checkpoint's own time like everything
	// else that decides whether a device counts (§5.3).
	at := proven.EvaluationTime(s.Result)
	for _, id := range proven.Devices(s.Result.State, at) {
		device := s.Result.State.Devices[id]
		row := deviceView{ID: id, Key: device.WgPk,
			Proof: proven.ProofDir + "/" + id + ".bundle"}
		if device.Expires > 0 {
			row.Expires = time.Unix(int64(device.Expires), 0).UTC().Format(time.RFC3339)
		}
		keys := make([]string, 0, len(device.Labels))
		for key := range device.Labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			row.Labels = append(row.Labels, labelView{Key: key, Value: device.Labels[key]})
		}
		view.Devices = append(view.Devices, row)
	}

	recent := s.Recent
	if recent <= 0 {
		recent = DefaultRecent
	}
	start := len(s.Result.Served) - recent
	if start < 0 {
		start = 0
	}
	for i := start; i < len(s.Result.Served); i++ {
		env, err := entry.Decode(s.Result.Served[i])
		if err != nil {
			continue
		}
		view.Recent = append(view.Recent, recentView{
			Index: int64(i), Words: plainlog.Describe(env)})
	}
	return view
}

// statusTemplate is `html/template`, which escapes by construction. Every
// value on this page came from somewhere somebody else controls -- a device's
// labels from whoever enrolled it, an alert's subject from a peer's name, the
// origin from the log operator -- so the escaping is the feature, not a
// formality.
var statusTemplate = template.Must(template.New("status").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>norn — {{.Name}}</title>
<style>
 body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem}
 h1{font-size:1.4rem;margin-bottom:0} .sub{color:#666}
 table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}
 th,td{text-align:left;padding:.35rem .6rem;border-bottom:1px solid #e5e5e5;vertical-align:top}
 th{font-weight:600;color:#444} code{font-family:ui-monospace,monospace;font-size:.9em}
 .critical{color:#a00;font-weight:600} .warning{color:#a60} .info{color:#555}
 .quiet{color:#777}
</style></head><body>
<h1>{{.Name}}</h1>
<p class="sub"><code>{{.Origin}}</code><br>anchor <code>{{.Fingerprint}}</code></p>

{{if .Verified}}
<h2>Checkpoint</h2>
<table>
 <tr><th>entries</th><td>{{.Size}}</td></tr>
 <tr><th>root</th><td><code>{{.Root}}</code></td></tr>
 {{if .CosignedAt}}<tr><th>cosigned</th><td>{{.CosignedAt}} <span class="quiet">({{.Age}} ago)</span></td></tr>
 {{else}}<tr><th>cosigned</th><td class="quiet">no witness has cosigned this head</td></tr>{{end}}
</table>

<h2>Witnesses</h2>
<table><tr><th>witness</th><th>cosigned at</th></tr>
{{range .Witnesses}}<tr><td><code>{{.Name}}</code></td><td>{{.CosignedAt}}</td></tr>{{end}}
</table>

<h2>Devices</h2>
<table><tr><th>device</th><th>key</th><th>labels</th><th>expires</th><th>proof</th></tr>
{{range .Devices}}<tr>
 <td>{{.ID}}</td><td><code>{{.Key}}</code></td>
 <td>{{range .Labels}}<code>{{.Key}}</code>={{.Value}}<br>{{end}}</td>
 <td>{{if .Expires}}{{.Expires}}{{else}}<span class="quiet">never</span>{{end}}</td>
 <td><a href="{{.Proof}}">{{.Proof}}</a></td>
</tr>{{end}}
</table>

<h2>Recent entries</h2>
<table>{{range .Recent}}<tr><td>{{.Index}}</td><td>{{.Words}}</td></tr>{{end}}</table>
{{else}}
<p class="quiet">nothing verified yet — this monitor has not managed to read the
log since it started.</p>
{{end}}

<h2>Alerts</h2>
{{if .Alerts}}
<table><tr><th>level</th><th>rule</th><th>what</th></tr>
{{range .Alerts}}<tr>
 <td class="{{.Level}}">{{.Level}}</td><td><code>{{.Rule}}</code></td><td>{{.Message}}</td>
</tr>{{end}}
</table>
{{else}}<p class="quiet">nothing open.</p>{{end}}
</body></html>
`))
