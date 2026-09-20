package monitor

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// `LAB.md` §3: "Read-only HTML on the tunnel address: checkpoint size/age,
// witness cosignature times, anchor status, device table with proof links,
// last 20 entries in plain words, open alerts. The Norn equivalent of a CT
// log's public page — and the thing you screenshot for the README."
//
// The security property is not obvious until you look at the fixture: a
// device's labels are chosen by whoever enrolled it, and the suite ships one
// whose labels contain `<`, `>` and `&` on purpose. A status page that let a
// label become markup would be a network where enrolling a device is enough to
// rewrite the page everybody reads.

func statusPage(t *testing.T, alerts []Alert) string {
	t.Helper()
	result := verifiedLog(t)
	page := Status{
		Network: anchorOf(t), Result: result, Alerts: alerts,
		Now: func() time.Time { return time.Unix(fixtureCosigned+300, 0) },
	}
	server := httptest.NewServer(page.Handler())
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content type = %q", ct)
	}
	body := make([]byte, 1<<20)
	n, _ := resp.Body.Read(body)
	return string(body[:n])
}

func TestTheStatusPageShowsWhatTheSectionAsksFor(t *testing.T) {
	page := statusPage(t, nil)

	result := verifiedLog(t)
	for _, want := range []string{
		strconv.FormatInt(result.Checkpoint.Size, 10), // checkpoint size
		"norn-testnet",    // the network's name
		"norn-witness/pi", // a witness, with its cosignature time
		"pi-cam",          // the device table
		"proofs/",         // proof links
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not mention %q", want)
		}
	}
	// The age, which is the number somebody is actually checking. Derived from
	// the checkpoint's own quorum time rather than assumed: the fixture's
	// witnesses cosign seven seconds apart now, so the age is measured from
	// the instant the *quorum* was reached and not from the first answer.
	if result.QuorumTime == nil {
		t.Fatal("the fixture's checkpoint has no quorum time")
	}
	age := time.Unix(fixtureCosigned+300, 0).Sub(*result.QuorumTime).Round(time.Second)
	if !strings.Contains(page, age.String()) {
		t.Errorf("the checkpoint age %s should be on the page:\n%s",
			age, firstLines(page, 40))
	}
}

// The one that matters. The fixture's `escaped` device has labels containing
// `<`, `>` and `&`, chosen by whoever enrolled it.
func TestADeviceLabelCannotBecomeMarkup(t *testing.T) {
	page := statusPage(t, nil)

	if !strings.Contains(page, "escaped") {
		t.Fatal("the device with the awkward labels is not on the page at all, so " +
			"this test proves nothing")
	}
	// The raw characters must not appear as markup.
	for _, forbidden := range []string{"<b&c", "x>y"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("%q appears unescaped; a device label became markup", forbidden)
		}
	}
	// And they must still be *readable*, escaped rather than dropped.
	if !strings.Contains(page, "&lt;") && !strings.Contains(page, "&amp;") {
		t.Error("the awkward label was dropped rather than escaped; an operator " +
			"cannot see what a device is actually called")
	}
}

// An alert with markup in it is the same problem arriving from a different
// direction -- a peer's name, a reason code, a log operator's origin.
func TestAnAlertCannotBecomeMarkup(t *testing.T) {
	page := statusPage(t, []Alert{{
		Rule: "fork-evidence", Level: Critical, Subject: "node<script>",
		Message: "<script>alert(1)</script> two histories",
	}})

	if strings.Contains(page, "<script>alert(1)</script>") {
		t.Error("an alert's text was rendered as markup")
	}
	if !strings.Contains(page, "two histories") {
		t.Error("the alert is not on the page at all")
	}
}

// Read-only, like every other surface Norn exposes on the tunnel.
func TestTheStatusPageTakesNoInstructions(t *testing.T) {
	page := Status{Network: anchorOf(t), Result: verifiedLog(t)}
	server := httptest.NewServer(page.Handler())
	t.Cleanup(server.Close)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req, err := http.NewRequest(method, server.URL+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s / = %d, want 405", method, resp.StatusCode)
		}
	}
}

// A monitor that has not managed to read anything yet still serves a page
// saying so, because a blank screen is indistinguishable from a broken one.
func TestAPageWithNothingToShowSaysSo(t *testing.T) {
	page := Status{Network: anchorOf(t)}
	server := httptest.NewServer(page.Handler())
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; a monitor with nothing to show still serves a page",
			resp.StatusCode)
	}
	body := make([]byte, 1<<16)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "nothing verified yet") {
		t.Errorf("the page should say why it is empty:\n%s", body[:n])
	}
}

// The last entries, in plain words -- the same renderer `norn status` uses, so
// the page and the terminal do not describe the same log differently.
func TestTheLastEntriesAreInPlainWords(t *testing.T) {
	page := statusPage(t, nil)

	if !strings.Contains(page, "enrolled") && !strings.Contains(page, "revoked") {
		t.Errorf("the recent entries should read as sentences:\n%s",
			firstLines(page, 60))
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
