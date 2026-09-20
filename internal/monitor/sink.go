package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// A Sink is somewhere an alert goes.
//
// `LAB.md` §3 lists five: ntfy, a Home Assistant webhook, Prometheus
// Alertmanager, stdout JSON and email. **All optional; stdout always.** That
// last word is the one worth defending: a monitor whose only record of an
// alert was a push that failed to send has no record at all, and the operator
// finds out by not finding out.
type Sink interface {
	Send(Alert) error
}

// DefaultSinkTimeout bounds one delivery. A phone service being slow must not
// hold up a monitoring round.
const DefaultSinkTimeout = 10 * time.Second

// Fanout sends to every sink and reports which ones failed.
//
// It never returns an error, only a list of failures, because there is nothing
// the caller should do differently: the alert has already happened. One broken
// sink must not silence the others -- the phone being unreachable is exactly
// when the file on disk matters.
type Fanout []Sink

// Send delivers to all sinks and returns each failure.
func (f Fanout) Send(alert Alert) []error {
	var failures []error
	for _, sink := range f {
		if err := sink.Send(alert); err != nil {
			failures = append(failures, err)
		}
	}
	return failures
}

// Stdout writes one JSON object per alert.
//
// This is the sink that is always on. It is machine-readable because something
// will eventually read it -- a log shipper, `jq`, a person at three in the
// morning -- and one object per line because that is the format all three can
// handle without a parser.
func Stdout(w io.Writer) Sink { return &stdout{w: w} }

type stdout struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *stdout) Send(alert Alert) error {
	raw, err := json.Marshal(map[string]any{
		"time": time.Now().UTC().Format(time.RFC3339), "rule": alert.Rule,
		"level": string(alert.Level), "subject": alert.Subject,
		"message": alert.Message,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = fmt.Fprintf(s.w, "%s\n", raw)
	return err
}

// HTTPSink is the shape the three network outputs share.
type HTTPSink struct {
	// URL is where to post.
	URL string
	// Timeout bounds one delivery; zero means DefaultSinkTimeout.
	Timeout time.Duration
	// build turns an alert into a request body and headers.
	build func(Alert) (body []byte, headers map[string]string, contentType string)
}

// Send posts one alert.
func (s *HTTPSink) Send(alert Alert) error {
	body, headers, contentType := s.build(alert)
	req, err := http.NewRequest(http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSinkTimeout
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", s.URL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s answered %d", s.URL, resp.StatusCode)
	}
	return nil
}

// ntfyPriority maps a level to what a phone sorts on.
//
// A fork arriving looking like an enrolment is the failure mode here: the
// whole point of a push is that the important one wakes somebody.
func ntfyPriority(level Level) string {
	switch level {
	case Critical:
		return "urgent"
	case Warning:
		return "high"
	default:
		return "default"
	}
}

// Ntfy pushes to an ntfy topic. `tags` are the emoji or labels ntfy shows.
func Ntfy(topicURL string, tags []string) *HTTPSink {
	return &HTTPSink{URL: topicURL, build: func(alert Alert) ([]byte, map[string]string, string) {
		title := string(alert.Level)
		if alert.Subject != "" {
			title = alert.Subject + ": " + string(alert.Level)
		}
		headers := map[string]string{
			"Title": title, "Priority": ntfyPriority(alert.Level),
		}
		if len(tags) > 0 {
			headers["Tags"] = strings.Join(tags, ",")
		}
		return []byte(alert.Message), headers, "text/plain; charset=utf-8"
	}}
}

// HomeAssistant posts to a webhook, which fires a `norn_alert` event an
// automation can subscribe to. The rule name is in the payload because that is
// what an automation matches on -- "turn the office light red on a fork" needs
// to know which rule fired, not to parse a sentence.
func HomeAssistant(webhookURL string) *HTTPSink {
	return &HTTPSink{URL: webhookURL, build: func(alert Alert) ([]byte, map[string]string, string) {
		raw, _ := json.Marshal(map[string]any{
			"event": "norn_alert", "rule": alert.Rule, "level": string(alert.Level),
			"subject": alert.Subject, "message": alert.Message,
		})
		return raw, nil, "application/json"
	}}
}

// Alertmanager posts to the v2 alerts API.
//
// The labels are the ones an operator routes on: `alertname` is the rule, and
// `severity` is the level under the name Alertmanager's own routing trees
// expect.
func Alertmanager(baseURL string) *HTTPSink {
	url := strings.TrimSuffix(baseURL, "/")
	if !strings.HasSuffix(url, "/api/v2/alerts") {
		url += "/api/v2/alerts"
	}
	return &HTTPSink{URL: url, build: func(alert Alert) ([]byte, map[string]string, string) {
		labels := map[string]string{
			"alertname": alert.Rule, "severity": string(alert.Level), "source": "norn",
		}
		if alert.Subject != "" {
			labels["subject"] = alert.Subject
		}
		raw, _ := json.Marshal([]map[string]any{{
			"labels":      labels,
			"annotations": map[string]string{"description": alert.Message},
		}})
		return raw, nil, "application/json"
	}}
}

// EmailConfig is what a mail sink needs.
type EmailConfig struct {
	From   string
	To     []string
	Server string // host:port
	// Username and Password are optional; many homelab relays want neither.
	Username, Password string
}

// EmailSink sends alerts as mail.
type EmailSink struct {
	cfg EmailConfig
	// send is the transport, a seam so the message this builds can be tested
	// without a mail server. There is no logic behind it worth mocking -- it
	// is `smtp.SendMail` -- and rather a lot of configuration that only a real
	// server can validate.
	send func(addr string, auth any, from string, to []string, msg []byte) error
}

// Email builds a mail sink.
func Email(cfg EmailConfig) *EmailSink {
	return &EmailSink{cfg: cfg, send: sendMail}
}

// Send builds an RFC 5322 message and hands it to the transport.
func (e *EmailSink) Send(alert Alert) error {
	subject := fmt.Sprintf("[%s] %s", alert.Level, alert.Subject)
	if alert.Subject == "" {
		subject = fmt.Sprintf("[%s] %s", alert.Level, alert.Rule)
	}
	// Headers, a blank line, then the body. Folded onto one line each and with
	// newlines stripped from the subject: an alert message is not attacker
	// input, but it is *generated* text, and a stray newline in a header is
	// how a generated message becomes two.
	var msg strings.Builder
	fmt.Fprintf(&msg, "From: %s\r\n", oneLine(e.cfg.From))
	fmt.Fprintf(&msg, "To: %s\r\n", oneLine(strings.Join(e.cfg.To, ", ")))
	fmt.Fprintf(&msg, "Subject: %s\r\n", oneLine(subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	msg.WriteString("\r\n")
	fmt.Fprintf(&msg, "%s\r\n\r\nrule: %s\r\nlevel: %s\r\n",
		alert.Message, alert.Rule, alert.Level)

	var auth any
	if e.cfg.Username != "" {
		auth = smtp.PlainAuth("", e.cfg.Username, e.cfg.Password,
			hostOf(e.cfg.Server))
	}
	return e.send(e.cfg.Server, auth, e.cfg.From, e.cfg.To, []byte(msg.String()))
}

// sendMail is the real transport.
func sendMail(addr string, auth any, from string, to []string, msg []byte) error {
	plain, _ := auth.(smtp.Auth)
	return smtp.SendMail(addr, plain, from, to, msg)
}

// oneLine strips the newlines that would turn one header into two.
func oneLine(value string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
}

func hostOf(server string) string {
	host, _, ok := strings.Cut(server, ":")
	if !ok {
		return server
	}
	return host
}
