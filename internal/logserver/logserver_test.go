package logserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlogstore"
)

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func logKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/logserver-test/log-key"))
	return ed25519.NewKeyFromSeed(seed[:])
}

// witnessKey is the in-process witness's own key. It used to be the log key
// under the cosignature algorithm, which D-066 refuses: a policy compares keys
// by the underlying public key, across `log` and `witness` lines alike.
func witnessKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/logserver-test/witness-key"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func fixtureSeed(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Ed25519 map[string]struct{ Seed string } `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(keys.Ed25519[name].Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("no seed for %q", name)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// testWitnessName is the single witness this package's logs are cosigned by.
const testWitnessName = "norn-witness/logserver-test"

// testPolicy is the anchor's side of that arrangement: one witness, and it
// must have cosigned. `quorum` may name a witness directly, so no group is
// needed for a one-witness network.
func testPolicy(t *testing.T, origin string) string {
	t.Helper()
	public := logKey(t).Public().(ed25519.PublicKey)
	witness := witnessKey(t).Public().(ed25519.PublicKey)
	return "log " + note.VerifierKey(origin, public) + "\n" +
		"witness " + testWitnessName + " " +
		note.CosignerVerifierKey(testWitnessName, witness) + "\n" +
		"quorum " + testWitnessName + "\n"
}

// theLog builds a server over the whole replay fixture: a real log, not a stub.
func theLog(t *testing.T) (*Server, *httptest.Server, replay.Anchor, string) {
	t.Helper()
	server, anchor, origin := seededServer(t)
	http := httptest.NewServer(server.Handler())
	t.Cleanup(http.Close)
	return server, http, anchor, origin
}

// seededServer uses the fixture without a listener, so write-side tests need no sockets.
func seededServer(t *testing.T, opts ...Option) (*Server, replay.Anchor, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Anchor struct {
			Net string `json:"net"`
			// Without this tag the field stays empty: Go matches JSON keys
			// case-insensitively but does not ignore underscores, so
			// `genesis_hash` never reaches `GenesisHash`.
			GenesisHash string `json:"genesis_hash"`
		} `json:"anchor"`
		Entries []struct{ Name string } `json:"entries"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	net, _ := hex.DecodeString(manifest.Anchor.Net)
	genesis, _ := hex.DecodeString(manifest.Anchor.GenesisHash)
	anchor := replay.Anchor{Net: net, GenesisHash: genesis}

	origin := "norn/logserver-test"
	dir := t.TempDir()
	// This log has one witness, and it runs in-process. A verifier checks the
	// quorum (§10 step 3), so a log that no witness corroborates is one these
	// tests could not verify -- and pretending otherwise here would hide the
	// very check the anchor exists to make.
	store, err := tlogstore.Open(dir, origin, logKey(t), tlogstore.WithCosigner(
		tlogstore.CosignerFunc(cosign.Append(
			[]cosign.Signer{{Name: testWitnessName, Key: witnessKey(t)}},
			cosign.At(time.Unix(1_760_003_600, 0))))))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range manifest.Entries {
		b, err := os.ReadFile(filepath.Join(vectorRoot(), "log", e.Name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Append(b); err != nil {
			t.Fatal(err)
		}
	}

	server, err := New(store, dir, origin, logKey(t), anchor, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return server, anchor, origin
}

// anEnroll builds a submittable entry: a real request signed by a real device
// key, wrapped in an entry signed by the fixture's two active signers.
func anEnroll(t *testing.T, anchor replay.Anchor, id string, after uint64) []byte {
	t.Helper()
	devicePub, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wg := make([]byte, 32)
	if _, err := rand.Read(wg); err != nil {
		t.Fatal(err)
	}
	request, err := enrollreq.New(anchor.Net, id, devicePub, wg, 1_760_100_000, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := enrollreq.Sign(request, devicePriv); err != nil {
		t.Fatal(err)
	}
	body, err := enrollreq.Encode(request)
	if err != nil {
		t.Fatal(err)
	}

	env := &entry.Envelope{V: entry.Version, T: "enroll", Net: anchor.Net,
		TS: 1_760_100_000, After: &after, Body: map[string]any{"request": body}}
	for _, name := range []string{"signer1", "signer3"} {
		if err := entry.Sign(env, fixtureSeed(t, name), "signer"); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func post(t *testing.T, url string, body []byte, contentType string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+AddPath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The test that decides this checkpoint: a submission is accepted, the receipt
// is a real signed promise about *that* entry, and the log is still a log --
// verifiable end to end, now containing the device.
func TestASubmissionIsAcceptedAndTheLogStillVerifies(t *testing.T) {
	server, ts, anchor, origin := theLog(t)
	raw := anEnroll(t, anchor, "submitted", 90)

	resp := post(t, ts.URL, raw, ContentType)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, readBody(t, resp))
	}
	receipt := readBody(t, resp)

	// §7: a signed note by the log key, naming this leaf.
	public := logKey(t).Public().(ed25519.PublicKey)
	text, err := note.Verify(receipt, []string{note.VerifierKey(origin, public)})
	if err != nil {
		t.Fatalf("the receipt does not verify under the log key: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 4 || lines[0] != note.ReceiptHeader || lines[1] != origin {
		t.Fatalf("receipt text is not §7's shape: %q", text)
	}
	wantLeaf, err := note.ReceiptText(origin, entry.LeafHash(raw), 0)
	if err != nil {
		t.Fatal(err)
	}
	if lines[2] != strings.Split(wantLeaf, "\n")[2] {
		t.Error("the receipt promises a different leaf than the one submitted")
	}

	// And the log a verifier reads is still whole, and now has the device.
	anchorWithKey := logclient.Anchor{Anchor: anchor,
		LogKeys: []string{note.VerifierKey(origin, public)}, Policy: testPolicy(t, origin)}
	result, err := logclient.Verify(logclient.HTTP(ts.URL), anchorWithKey)
	if err != nil {
		t.Fatalf("the log stopped verifying after a submission: %v", err)
	}
	// One more than the fixture, whatever the fixture is: a literal here went
	// stale the moment the replay fixture gained an entry.
	if want := fixtureSize(t) + 1; result.Checkpoint.Size != server.store.Size() ||
		result.Checkpoint.Size != want {
		t.Errorf("size = %d, want %d", result.Checkpoint.Size, want)
	}
	device, ok := result.State.Devices["submitted"]
	if !ok || device.Status != state.StatusActive {
		t.Errorf("the submitted device is not active: %+v", device)
	}
}

// A client whose connection dropped after the append has an entry in the log
// and no receipt. Answering `dup-entry` would be true and useless.
func TestResubmittingIsIdempotent(t *testing.T) {
	server, ts, anchor, _ := theLog(t)
	raw := anEnroll(t, anchor, "twice", 90)

	first := post(t, ts.URL, raw, ContentType)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first: %d %s", first.StatusCode, readBody(t, first))
	}
	sizeAfterFirst := server.store.Size()

	second := post(t, ts.URL, raw, ContentType)
	if second.StatusCode != http.StatusOK {
		t.Fatalf("second: %d %s", second.StatusCode, readBody(t, second))
	}
	if got := server.store.Size(); got != sizeAfterFirst {
		t.Errorf("the log grew to %d on a resubmission, want %d", got, sizeAfterFirst)
	}
	if body := readBody(t, second); !strings.HasPrefix(body, note.ReceiptHeader) {
		t.Errorf("a resubmission must still return a receipt, got %q", body)
	}
}

func TestRejectedEntriesAreRefusedWithTheirReason(t *testing.T) {
	_, ts, anchor, _ := theLog(t)

	// `nas` is active in the fixture, so enrolling it again is `dup-id`.
	resp := post(t, ts.URL, anEnroll(t, anchor, "nas", 90), ContentType)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "dup-id") {
		t.Errorf("the reason code belongs in the response: %q", body)
	}
	// §6: the check is a courtesy, and the response should say so rather than
	// let an implementer take it for authority.
	if !strings.Contains(body, "advisory") {
		t.Errorf("the response should say the check is advisory: %q", body)
	}
}

func TestMalformedSubmissions(t *testing.T) {
	_, ts, anchor, _ := theLog(t)
	good := anEnroll(t, anchor, "fine", 90)

	cases := []struct {
		why         string
		body        []byte
		contentType string
		want        int
	}{
		{"not CBOR", []byte("hello"), ContentType, http.StatusBadRequest},
		{"empty", nil, ContentType, http.StatusBadRequest},
		{"wrong content type", good, "application/json", http.StatusBadRequest},
		{"no content type", good, "", http.StatusBadRequest},
		{"truncated entry", good[:len(good)/2], ContentType, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			if got := post(t, ts.URL, c.body, c.contentType).StatusCode; got != c.want {
				t.Errorf("status = %d, want %d", got, c.want)
			}
		})
	}
}

func TestAnEntryForAnotherNetworkIsRefused(t *testing.T) {
	_, ts, anchor, _ := theLog(t)
	other := replay.Anchor{Net: bytes.Repeat([]byte{9}, 16), GenesisHash: anchor.GenesisHash}
	resp := post(t, ts.URL, anEnroll(t, other, "elsewhere", 90), ContentType)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestGettingAddIsNotAllowed(t *testing.T) {
	_, ts, _, _ := theLog(t)
	resp, err := http.Get(ts.URL + AddPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
	if resp.Header.Get("Allow") != http.MethodPost {
		t.Errorf("a 405 should say what is allowed, got %q", resp.Header.Get("Allow"))
	}
}

// The gate's claim is that a plain static server is enough for the read side.
// These are the files it would serve.
func TestTheReadSideIsJustFiles(t *testing.T) {
	_, ts, _, origin := theLog(t)
	resp, err := http.Get(ts.URL + "/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	public := logKey(t).Public().(ed25519.PublicKey)
	if _, err := note.Verify(string(body), []string{note.VerifierKey(origin, public)}); err != nil {
		t.Errorf("the served checkpoint must be the signed note: %v", err)
	}
}

// The store appends to a tree and rewrites files; two submissions at once would
// interleave into a log that is not a log.
func TestConcurrentSubmissionsAllLand(t *testing.T) {
	server, ts, anchor, origin := theLog(t)
	const n = 8

	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw := anEnroll(t, anchor, fmt.Sprintf("concurrent-%d", i), 90)
			codes[i] = post(t, ts.URL, raw, ContentType).StatusCode
		}(i)
	}
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("submission %d: status %d", i, code)
		}
	}
	if want := fixtureSize(t) + int64(n); server.store.Size() != want {
		t.Fatalf("size = %d, want %d", server.store.Size(), want)
	}

	public := logKey(t).Public().(ed25519.PublicKey)
	result, err := logclient.Verify(logclient.HTTP(ts.URL),
		logclient.Anchor{Anchor: anchor, LogKeys: []string{note.VerifierKey(origin, public)},
			Policy: testPolicy(t, origin)})
	if err != nil {
		t.Fatalf("the log is not verifiable after concurrent writes: %v", err)
	}
	if len(result.State.Rejected) > 0 {
		t.Logf("checkpoint size %d, %d rejections, last: %+v", result.Checkpoint.Size,
			len(result.State.Rejected), result.State.Rejected[len(result.State.Rejected)-1])
	}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("concurrent-%d", i)
		if d, ok := result.State.Devices[id]; !ok || d.Status != state.StatusActive {
			t.Errorf("%s did not land", id)
		}
	}
}

// fixtureSize is how many entries the replay fixture has, read from its
// manifest rather than spelled out.
func fixtureSize(t *testing.T) int64 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Entries []struct{} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return int64(len(m.Entries))
}

// SEC-001 (D-070). `sigs` sits outside every signature's preimage, and an
// unresolvable signature is ignored, so a past entry plus one junk signature
// is new bytes with the original signatures still counting. `37-enroll-spare`
// re-appended that way re-enrols a device revoked at entry 39, and this
// log's own replay would accept it today. The log refuses it by its signed
// content, naming where that content already is -- which is not the
// idempotent resubmission above: those bytes are already in the log.
func TestAReSignedCopyOfAnEntryIsRefusedNamingTheOriginal(t *testing.T) {
	_, ts, _, _ := theLog(t)
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log", "37-enroll-spare.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Sorted last, so the decoder's ordering rule does not refuse it first --
	// and a different junk kid from the fixture's own copy (`bad-copy-enroll-
	// spare-extra-sig`, D-070), or these would be that entry's exact bytes
	// and the idempotent resubmission above would answer with its receipt.
	env.Sigs = append(env.Sigs, entry.Signature{Kid: "fffffffffffffff0", Role: "signer",
		Sig: make([]byte, ed25519.SignatureSize)})
	copy, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(copy, raw) {
		t.Fatal("the copy is byte-identical; nothing here is tested")
	}

	resp := post(t, ts.URL, copy, ContentType)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("a re-signed copy of entry 37 was answered %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "37") || !strings.Contains(body, "signed content") {
		t.Errorf("the refusal should name the index that already holds this signed "+
			"content: %q", body)
	}
}
