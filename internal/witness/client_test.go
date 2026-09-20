package witness

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
)

// `c2sp.org/tlog-witness`, fetched rather than recalled -- the habit that found
// the algorithm-byte defect in 4.1a.
//
//	POST <prefix>/add-checkpoint
//	old <size>\n
//	<zero or more base64 consistency hashes, one per line>
//	\n
//	<the signed checkpoint>
//
// 200 returns one or more cosignature lines. 404, 403, 400, 409 and 422 each
// mean something different, and 409 carries the witness's own tree size.

const origin = "example.com/behind-the-sofa"

func key(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/witness-test/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func public(t *testing.T, k ed25519.PrivateKey) ed25519.PublicKey {
	t.Helper()
	return k.Public().(ed25519.PublicKey)
}

// aCheckpoint is a head as the log publishes it: signed, not yet cosigned.
func aCheckpoint(t *testing.T) (signed, body string) {
	t.Helper()
	body = origin + "\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
	signed, err := note.Sign(body, origin, key(t, "log"))
	if err != nil {
		t.Fatal(err)
	}
	return signed, body
}

func witnessKey(t *testing.T) string {
	t.Helper()
	return note.CosignerVerifierKey("witness.example/w1", public(t, key(t, "witness")))
}

// serve stands up a witness that runs `handler` and returns a client for it.
func serve(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &Client{Name: "w1", URL: server.URL, Key: witnessKey(t)}
}

// cosignWith answers as a witness does: the cosignature lines, nothing else.
func cosignWith(t *testing.T, body string) string {
	t.Helper()
	line, err := cosign.Sign(body, "witness.example/w1", key(t, "witness"),
		time.Unix(1_760_003_600, 0))
	if err != nil {
		t.Fatal(err)
	}
	return line + "\n"
}

// aProof is a syntactically valid consistency proof; the witness checks it,
// this package does not.
func aProof() [][]byte { return [][]byte{make([]byte, 32)} }

func TestTheRequestIsTheDocumentedShape(t *testing.T) {
	signed, body := aCheckpoint(t)
	var path, method, sent string
	client := serve(t, func(w http.ResponseWriter, r *http.Request) {
		path, method = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		sent = string(raw)
		_, _ = w.Write([]byte(cosignWith(t, body)))
	})

	proof := [][]byte{make([]byte, 32), make([]byte, 32)}
	proof[0][0], proof[1][0] = 1, 2
	if _, err := client.Add(signed, 20852014, proof); err != nil {
		t.Fatal(err)
	}

	if method != http.MethodPost {
		t.Errorf("method = %s, want POST", method)
	}
	if !strings.HasSuffix(path, "/add-checkpoint") {
		t.Errorf("path = %q, want it to end in /add-checkpoint", path)
	}
	lines := strings.SplitAfter(sent, "\n")
	if lines[0] != "old 20852014\n" {
		t.Errorf("first line = %q, want the old size", lines[0])
	}
	// Two proof lines, then an empty line, then the checkpoint verbatim.
	if lines[1] != "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" {
		t.Errorf("proof line = %q", lines[1])
	}
	if lines[3] != "\n" {
		t.Errorf("line 4 = %q, want the empty line that separates proof from checkpoint", lines[3])
	}
	if got := strings.Join(lines[4:], ""); got != signed {
		t.Errorf("the checkpoint was altered in transit:\n got %q\nwant %q", got, signed)
	}
}

// "The proof MUST be empty if the old size is zero."
func TestAProofWithOldSizeZeroIsRefused(t *testing.T) {
	signed, _ := aCheckpoint(t)
	client := serve(t, func(http.ResponseWriter, *http.Request) {})

	if _, err := client.Add(signed, 0, [][]byte{make([]byte, 32)}); err == nil {
		t.Fatal("a consistency proof was sent with an old size of zero")
	}
}

func TestAFirstSubmissionSendsNoProof(t *testing.T) {
	signed, body := aCheckpoint(t)
	var sent string
	client := serve(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		sent = string(raw)
		_, _ = w.Write([]byte(cosignWith(t, body)))
	})

	if _, err := client.Add(signed, 0, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sent, "old 0\n\n") {
		t.Errorf("body should be `old 0`, an empty line, then the checkpoint:\n%q", sent)
	}
}

// A witness may hold several keys and return a line for each.
func TestEveryReturnedCosignatureIsKept(t *testing.T) {
	signed, body := aCheckpoint(t)
	second, err := cosign.Sign(body, "witness.example/w2", key(t, "witness2"),
		time.Unix(1_760_003_600, 0))
	if err != nil {
		t.Fatal(err)
	}
	client := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(cosignWith(t, body) + second + "\n"))
	})
	client.AlsoTrust = []string{
		note.CosignerVerifierKey("witness.example/w2", public(t, key(t, "witness2")))}

	lines, err := client.Add(signed, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("kept %d cosignatures, want 2: %q", len(lines), lines)
	}
}

// A witness that answers with a cosignature over some *other* checkpoint --
// or a middlebox that rewrites one -- must be caught here. Serving it would
// publish a head every verifier then refuses, with nothing to say why.
func TestACosignatureThatDoesNotVerifyIsRefused(t *testing.T) {
	signed, _ := aCheckpoint(t)
	client := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(cosignWith(t, "some other log\n7\nAAAA=\n")))
	})

	if _, err := client.Add(signed, 0, nil); err == nil {
		t.Fatal("a cosignature over another checkpoint was accepted")
	}
}

// A witness answering 200 with nothing is not success.
func TestAnEmptySuccessIsRefused(t *testing.T) {
	signed, _ := aCheckpoint(t)
	client := serve(t, func(w http.ResponseWriter, r *http.Request) {})

	if _, err := client.Add(signed, 0, nil); err == nil {
		t.Fatal("an empty 200 was treated as a cosignature")
	}
}

// 409 is the one error that carries data: the witness's own tree size, which
// is how a log learns what to prove consistency from. Losing it would leave
// the log retrying the same rejected request forever.
func TestAConflictCarriesTheWitnessSize(t *testing.T) {
	signed, _ := aCheckpoint(t)
	client := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x.tlog.size")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("20852014\n"))
	})

	_, err := client.Add(signed, 99, aProof())
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("409 did not produce a ConflictError: %v", err)
	}
	if conflict.WitnessSize != 20852014 {
		t.Errorf("witness size = %d, want 20852014", conflict.WitnessSize)
	}
}

// A 409 whose body is not a size is a protocol violation, and guessing would
// mean retrying blind.
func TestAConflictWithoutASizeIsAnError(t *testing.T) {
	signed, _ := aCheckpoint(t)
	client := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("<html>gateway error</html>"))
	})

	_, err := client.Add(signed, 99, aProof())
	var conflict *ConflictError
	if errors.As(err, &conflict) {
		t.Fatal("a gateway error page was read as a tree size")
	}
	if err == nil {
		t.Fatal("no error at all")
	}
}

// Each status means a different thing for an operator to do, so each is told
// apart rather than collapsed into "the witness said no".
func TestEveryDocumentedStatusIsNamed(t *testing.T) {
	signed, _ := aCheckpoint(t)
	for _, tc := range []struct {
		status int
		says   string
	}{
		{http.StatusNotFound, "does not know"},
		{http.StatusForbidden, "does not trust"},
		{http.StatusBadRequest, "older than"},
		{http.StatusUnprocessableEntity, "consistency"},
		{http.StatusInternalServerError, "500"},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			client := serve(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			})
			_, err := client.Add(signed, 0, nil)
			if err == nil {
				t.Fatalf("%d was treated as success", tc.status)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the error should say %q: %v", tc.says, err)
			}
		})
	}
}

// A 422 means the witness could not verify consistency from what it holds to
// what we sent. That is either our bug or the log having forked, and the
// second is the one worth naming on sight.
func TestAConsistencyFailureNamesTheFork(t *testing.T) {
	signed, _ := aCheckpoint(t)
	client := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	})

	_, err := client.Add(signed, 5, aProof())
	if err == nil || !strings.Contains(err.Error(), "fork") {
		t.Errorf("a consistency failure must raise the possibility of a fork: %v", err)
	}
}

// A consistency proof between two *different* sizes is required; from a size
// to itself it is empty and correct. That is what resubmitting a head the
// witness has already cosigned looks like, so it must not be refused locally.
func TestResubmittingTheSameSizeNeedsNoProof(t *testing.T) {
	signed, body := aCheckpoint(t)
	client := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(cosignWith(t, body)))
	})

	if _, err := client.Add(signed, 20852163, nil); err != nil {
		t.Errorf("a same-size resubmission was refused locally: %v", err)
	}
}

// And a proof from a size the checkpoint is *behind* is this log's own bug,
// caught before it becomes the witness's 400.
func TestAnOldSizeAheadOfTheCheckpointIsRefused(t *testing.T) {
	signed, _ := aCheckpoint(t)
	client := serve(t, func(http.ResponseWriter, *http.Request) {})

	if _, err := client.Add(signed, 30000000, nil); err == nil {
		t.Fatal("an old size ahead of the checkpoint was sent")
	}
}

// The specification's own example request, reproduced byte for byte.
//
// Everything else here checks this package against itself; this checks it
// against the document. If the separator, the ordering, the base64 alphabet or
// the trailing newline were wrong in the same way in both the writer and the
// reader, only bytes somebody else wrote would notice.
func TestTheRequestMatchesTheSpecificationsOwnExample(t *testing.T) {
	const submitted = "example.com/behind-the-sofa\n" +
		"20852163\n" +
		"CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n" +
		"\n" +
		"— example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeO" +
		"oRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=\n" +
		"— example.com/behind-the-sofa opLqBQsREYCgu6xQkYQwJr9fo45a62DN9EdmHXnZdXNq" +
		"lcVGlCum2Wks+49/V6267UEjw6QUXTS5Rovnzv++qbSzm9Q=\n"

	const want = "old 20852014\n" +
		"PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=\n" +
		"jrJZDmY8Y7SyJE0MWLpLozkIVMSMZcD5kvuKxPC3swk=\n" +
		"5+pKlUdi2LeF/BcMHBn+Ku6yhPGNCswZZD1X/6QgPd8=\n" +
		"/6WVhPs2CwSsb5rYBH5cjHV/wSmA79abXAwhXw3Kj/0=\n" +
		"\n" + submitted

	var proof [][]byte
	for _, encoded := range []string{
		"PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=",
		"jrJZDmY8Y7SyJE0MWLpLozkIVMSMZcD5kvuKxPC3swk=",
		"5+pKlUdi2LeF/BcMHBn+Ku6yhPGNCswZZD1X/6QgPd8=",
		"/6WVhPs2CwSsb5rYBH5cjHV/wSmA79abXAwhXw3Kj/0=",
	} {
		hash, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		proof = append(proof, hash)
	}

	client := &Client{Name: "w1", URL: "http://witness.invalid"}
	got, err := client.request(submitted, 20852014, proof)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("the request is not what the specification shows:\n got %q\nwant %q",
			got, want)
	}
}
