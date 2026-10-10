package main

import (
	"net/http"

	"github.com/onembyte/norn/internal/agent"
	"github.com/onembyte/norn/internal/gossip"
	"github.com/onembyte/norn/internal/metrics"
)

// gossipHandler adds observations beside the gossip byte server, only on its
// tunnel listener. Counts are for operators, never claims a peer must trust:
// peers still verify the signed bytes from /norn/ and consult no metrics.
func gossipHandler(mirror, evidence string, cycle *agent.Agent) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", gossip.Handler(mirror, evidence))
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		_ = metrics.Write(w, cycle.Metrics())
	})
	return mux
}
