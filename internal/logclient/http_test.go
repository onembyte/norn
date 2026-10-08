package logclient

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The gate says "served by plain nginx". What that actually requires of Norn
// is that the log be *static files over HTTP with no server-side logic* -- so
// a stock file server is the honest test of it, and Go's is one.

func TestVerifyOverPlainHTTP(t *testing.T) {
	dir, anchor := servedLog(t)
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()

	result, err := Verify(HTTP(srv.URL), anchor)
	if err != nil {
		t.Fatalf("verify over HTTP: %v", err)
	}
	if result.State.Size == 0 || len(result.State.Devices) == 0 {
		t.Fatal("verifying over HTTP produced an empty state")
	}
	// The same log, read two ways, must give the same answer.
	viaDir, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}
	overHTTP, _ := result.State.MarshalCanonical()
	overDir, _ := viaDir.State.MarshalCanonical()
	if string(overHTTP) != string(overDir) {
		t.Error("reading the same log over HTTP and from disk gave different states")
	}
	if result.Checkpoint != viaDir.Checkpoint {
		t.Error("checkpoints differ between transports")
	}
}

func TestHTTPFetchTreatsA404AsAMissingFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if _, err := HTTP(srv.URL).Fetch("checkpoint"); err == nil {
		t.Error("a 404 must be an error, not empty content")
	}
}

func TestHTTPFetchRejectsAnOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A hostile or broken server must not be able to exhaust a verifier's
		// memory just by answering a request.
		chunk := make([]byte, 1<<20)
		for i := 0; i < 64; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	if _, err := HTTP(srv.URL).Fetch("checkpoint"); err == nil {
		t.Error("an oversized response must be refused")
	}
}

func TestHTTPFetchRefusesPathEscape(t *testing.T) {
	dir, _ := servedLog(t)
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()

	if _, err := HTTP(srv.URL).Fetch("../../../etc/passwd"); err == nil {
		t.Error("a path that escapes the log root must be refused before it is sent")
	}
}

// SEC-003 (H2-a). `Submit` used `http.Post` -- the default client, no
// deadline -- so a log that accepted the connection and never answered held
// `norn enroll` forever. Reads already had a bound; a submission gets the
// same one.
func TestSubmitDoesNotWaitForeverOnASilentLog(t *testing.T) {
	was := Timeout
	Timeout = 300 * time.Millisecond
	t.Cleanup(func() { Timeout = was })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var held []net.Conn
	done := make(chan struct{})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(done)
				return
			}
			held = append(held, c)
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-done
		for _, c := range held {
			c.Close()
		}
	})

	started := time.Now()
	_, _, err = Submit("http://"+l.Addr().String(), []byte("an entry"))
	took := time.Since(started)
	if err == nil {
		t.Fatal("a log that never answers produced a receipt")
	}
	if took > 5*time.Second {
		t.Fatalf("a silent log held the submitter for %s; the bound is %s", took, Timeout)
	}
}
