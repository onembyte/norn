package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// `LAB.md` §3: "ntfy · Home Assistant webhook · Prometheus Alertmanager ·
// stdout JSON · email. **All optional; stdout always.**"
//
// The "always" is the part worth defending. A monitor whose only record of an
// alert was a push that failed to send has no record at all, and the operator
// finds out by not finding out.

func anAlert() Alert {
	return Alert{Rule: "fork-evidence", Level: Critical, Subject: "node2",
		Message: "node2 proved this network's log signed two histories"}
}

func TestStdoutWritesOneJSONObjectPerAlert(t *testing.T) {
	var out bytes.Buffer
	sink := Stdout(&out)

	if err := sink.Send(anAlert()); err != nil {
		t.Fatal(err)
	}
	if err := sink.Send(Alert{Rule: "new-entry", Level: Info, Message: "enrolled pi-cam"}); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("wrote %d lines for two alerts", len(lines))
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 1 is not JSON: %v", err)
	}
	for _, key := range []string{"rule", "level", "message"} {
		if _, ok := first[key]; !ok {
			t.Errorf("the object has no %q: %v", key, first)
		}
	}
}

func TestNtfyCarriesThePriorityAndTheMessage(t *testing.T) {
	var gotBody, gotPriority, gotTitle string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 1024)
		n, _ := r.Body.Read(raw)
		gotBody = string(raw[:n])
		gotPriority = r.Header.Get("Priority")
		gotTitle = r.Header.Get("Title")
	}))
	defer server.Close()

	if err := Ntfy(server.URL, nil).Send(anAlert()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotBody, "two histories") {
		t.Errorf("body = %q", gotBody)
	}
	// A phone sorts by priority, so a fork must not arrive looking like an
	// enrolment.
	if gotPriority != "urgent" {
		t.Errorf("priority = %q, want urgent for a critical alert", gotPriority)
	}
	if !strings.Contains(gotTitle, "node2") {
		t.Errorf("title = %q, want the subject in it", gotTitle)
	}
}

func TestNtfyRanksInfoBelowCritical(t *testing.T) {
	var priorities []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		priorities = append(priorities, r.Header.Get("Priority"))
	}))
	defer server.Close()
	sink := Ntfy(server.URL, nil)

	for _, level := range []Level{Info, Warning, Critical} {
		if err := sink.Send(Alert{Rule: "r", Level: level, Message: "m"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(priorities) != 3 || priorities[0] == priorities[2] {
		t.Errorf("priorities = %v; an info and a critical must not look alike",
			priorities)
	}
}

// Home Assistant gets a webhook that fires a `norn_alert` event, which is what
// an automation subscribes to.
func TestHomeAssistantPostsTheAlertAsJSON(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer server.Close()

	if err := HomeAssistant(server.URL).Send(anAlert()); err != nil {
		t.Fatal(err)
	}
	if got["level"] != string(Critical) {
		t.Errorf("payload = %v", got)
	}
	if got["rule"] != "fork-evidence" {
		t.Errorf("the rule should be in the payload so an automation can match on "+
			"it: %v", got)
	}
}

// Alertmanager takes labels, and the ones that matter are the ones an operator
// routes on.
func TestAlertmanagerSendsLabelsItCanRouteOn(t *testing.T) {
	var got []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer server.Close()

	if err := Alertmanager(server.URL).Send(anAlert()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("sent %d alerts", len(got))
	}
	labels, _ := got[0]["labels"].(map[string]any)
	for _, key := range []string{"alertname", "severity"} {
		if _, ok := labels[key]; !ok {
			t.Errorf("labels = %v, want %q", labels, key)
		}
	}
}

// The property the whole file exists for: one broken sink must not silence the
// others, and must not stop the monitor.
func TestOneBrokenSinkDoesNotSilenceTheRest(t *testing.T) {
	var out bytes.Buffer
	var delivered bool
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered = true
	}))
	defer working.Close()

	fan := Fanout{
		Stdout(&out),
		sinkFunc(func(Alert) error { return errors.New("the phone service is down") }),
		HomeAssistant(working.URL),
	}

	failures := fan.Send(anAlert())

	if len(failures) != 1 {
		t.Errorf("failures = %v, want exactly the broken one", failures)
	}
	if out.Len() == 0 {
		t.Error("stdout was silenced by another sink failing")
	}
	if !delivered {
		t.Error("a later sink never ran because an earlier one failed")
	}
}

// A sink that hangs must not hang the monitor.
func TestASinkThatNeverAnswersTimesOut(t *testing.T) {
	blocked := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked
	}))
	// Order matters: httptest.Server.Close waits for outstanding handlers, so
	// the handler has to be released before the server is closed. Deferring
	// them the other way round deadlocks the test rather than the code.
	defer server.Close()
	defer close(blocked)

	sink := Ntfy(server.URL, nil)
	sink.Timeout = 50 * time.Millisecond

	if err := sink.Send(anAlert()); err == nil {
		t.Error("a sink that never answered reported success")
	}
}

// An unconfigured output is not an error: "all optional".
func TestAnEmptyFanoutIsFine(t *testing.T) {
	if failures := (Fanout{}).Send(anAlert()); len(failures) != 0 {
		t.Errorf("failures = %v", failures)
	}
}

type sinkFunc func(Alert) error

func (f sinkFunc) Send(a Alert) error { return f(a) }

// Email is the one output whose transport cannot be meaningfully tested
// without a mail server, so the split is deliberate: the message it builds is
// tested here, and the five-line `net/smtp` call is a seam.
func TestEmailBuildsAMessageAMailerWillAccept(t *testing.T) {
	var to []string
	var body string
	sink := Email(EmailConfig{
		From: "norn@example.org", To: []string{"franco@example.org"},
		Server: "mail.example.org:587",
	})
	sink.send = func(addr string, auth any, from string, rcpt []string, msg []byte) error {
		to, body = rcpt, string(msg)
		return nil
	}

	if err := sink.Send(anAlert()); err != nil {
		t.Fatal(err)
	}
	if len(to) != 1 || to[0] != "franco@example.org" {
		t.Errorf("recipients = %v", to)
	}
	// The headers a mail server requires, and a subject a person can triage
	// from a lock screen without opening it.
	for _, want := range []string{
		"From: norn@example.org", "To: franco@example.org",
		"Subject: [critical] node2", "MIME-Version: 1.0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the message has no %q:\n%s", want, body)
		}
	}
	// Headers and body are separated by a blank line, or it is not a message.
	headers, rest, ok := strings.Cut(body, "\r\n\r\n")
	if !ok {
		t.Fatalf("no header/body separator:\n%q", body)
	}
	if strings.Contains(headers, "two histories") {
		t.Error("the alert text ended up in the headers")
	}
	if !strings.Contains(rest, "two histories") {
		t.Errorf("body = %q", rest)
	}
}

// A mail server that refuses is one failed sink, not a failed round.
func TestAnEmailFailureIsJustAFailedSink(t *testing.T) {
	sink := Email(EmailConfig{From: "a@b", To: []string{"c@d"}, Server: "s:25"})
	sink.send = func(string, any, string, []string, []byte) error {
		return errors.New("relay access denied")
	}

	failures := Fanout{sink, Stdout(&bytes.Buffer{})}.Send(anAlert())
	if len(failures) != 1 {
		t.Errorf("failures = %v, want just the mail one", failures)
	}
}
