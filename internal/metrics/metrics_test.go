package metrics

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var expectedFamilies = map[string]string{
	"norn_checkpoint_size": "gauge", "norn_checkpoint_age_seconds": "gauge", "norn_state": "gauge",
	"norn_gossip_peers_polled_total": "counter", "norn_gossip_adopted_from": "counter", "norn_fork_evidence_total": "counter",
	"norn_replay_rejected_total": "counter", "norn_clock_skew_seconds": "gauge", "norn_reconcile_seconds": "histogram",
	"norn_evicted_peers_total": "counter", "norn_unproven_peers": "gauge",
}

func exposition(t *testing.T) string {
	t.Helper()
	s := Snapshot{CheckpointSize: 90, CheckpointAge: 960, State: "fresh", PeersPolled: 3, AdoptedLog: 1, AdoptedPeer: 2, ForkEvidence: 1, ReplayRejected: 9, ClockSkew: -60, EvictedPeers: 4, UnprovenPeers: 2}
	for _, duration := range []float64{0.00005, 0.007, 0.2, 12} {
		s.Reconcile.Observe(duration)
	}
	var b bytes.Buffer
	if err := Write(&b, s); err != nil {
		t.Fatal(err)
	}
	return b.String()
}
func TestExactlyTheElevenMetricFamiliesAreDeclared(t *testing.T) {
	found := map[string]string{}
	for _, line := range strings.Split(exposition(t), "\n") {
		if strings.HasPrefix(line, "# TYPE ") {
			fields := strings.Fields(line)
			if len(fields) != 4 {
				t.Fatal(line)
			}
			found[fields[2]] = fields[3]
		}
	}
	if len(found) != len(expectedFamilies) {
		t.Fatalf("declared %d families, want eleven: %v", len(found), found)
	}
	for name, kind := range expectedFamilies {
		if found[name] != kind {
			t.Errorf("%s type = %q, want %s", name, found[name], kind)
		}
	}
}

// Parsing is independent of the writer: declarations precede samples, labels
// have the three exposition escapes, and cumulative buckets cover the count.
func TestTheWholeOutputParsesAsTextExposition(t *testing.T) {
	sample := regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})? ([^ ]+)$`)
	label := regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\\n]|\\[\\"n])*)"(?:,|$)`)
	declared := map[string]string{}
	help := map[string]bool{}
	seen := map[string]bool{}
	buckets := map[float64]float64{}
	var sum, count float64
	for _, line := range strings.Split(exposition(t), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# HELP ") {
			f := strings.SplitN(line, " ", 4)
			if len(f) != 4 || f[3] == "" {
				t.Fatal(line)
			}
			help[f[2]] = true
			continue
		}
		if strings.HasPrefix(line, "# TYPE ") {
			f := strings.Fields(line)
			if len(f) != 4 || declared[f[2]] != "" || !help[f[2]] {
				t.Fatal(line)
			}
			declared[f[2]] = f[3]
			continue
		}
		m := sample.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("bad sample: %s", line)
		}
		name := m[1]
		family := name
		for _, suffix := range []string{"_bucket", "_sum", "_count"} {
			if strings.HasSuffix(name, suffix) && declared[strings.TrimSuffix(name, suffix)] == "histogram" {
				family = strings.TrimSuffix(name, suffix)
			}
		}
		if declared[family] == "" {
			t.Fatalf("sample before TYPE: %s", line)
		}
		if seen[name+m[2]] {
			t.Fatalf("duplicate sample: %s", line)
		}
		seen[name+m[2]] = true
		value, err := strconv.ParseFloat(m[4], 64)
		if err != nil {
			t.Fatal(err)
		}
		labels := map[string]string{}
		rest := m[3]
		for rest != "" {
			l := label.FindStringSubmatch(rest)
			if l == nil {
				t.Fatalf("unquoted or invalid escape: %s", line)
			}
			if _, exists := labels[l[1]]; exists {
				t.Fatal(line)
			}
			labels[l[1]] = l[2]
			rest = rest[len(l[0]):]
		}
		switch name {
		case "norn_state":
			if len(labels) != 1 || !strings.Contains(" fresh degraded hard_stale fork ", " "+labels["state"]+" ") {
				t.Fatal(line)
			}
		case "norn_gossip_adopted_from":
			if len(labels) != 1 || (labels["source"] != "log" && labels["source"] != "peer") {
				t.Fatal(line)
			}
		case "norn_reconcile_seconds_bucket":
			if len(labels) != 1 {
				t.Fatal(line)
			}
			bound, err := strconv.ParseFloat(labels["le"], 64)
			if err != nil {
				t.Fatal(err)
			}
			buckets[bound] = value
		default:
			if len(labels) != 0 {
				t.Fatal(line)
			}
		}
		if name == "norn_reconcile_seconds_sum" {
			sum = value
		}
		if name == "norn_reconcile_seconds_count" {
			count = value
		}
	}
	if len(declared) != 11 || len(seen) != 25 {
		t.Fatalf("incomplete exposition: %d families, %d samples", len(declared), len(seen))
	}
	previous := 0.0
	for _, bound := range ReconcileBounds() {
		v, ok := buckets[bound]
		if !ok || v < previous || v > count {
			t.Fatalf("inconsistent bucket %g: %g", bound, v)
		}
		previous = v
	}
	if buckets[math.Inf(1)] != count || count != 4 || math.Abs(sum-12.20705) > 1e-9 {
		t.Fatalf("histogram sum=%g count=%g buckets=%v", sum, count, buckets)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("write failed") }
func TestExpositionReportsWriteFailures(t *testing.T) {
	if Write(failingWriter{}, Snapshot{State: "fresh"}) == nil {
		t.Fatal("lost writer error")
	}
}
