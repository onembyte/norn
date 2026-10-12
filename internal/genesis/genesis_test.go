package genesis

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

func keys(t *testing.T, n int) ([]ed25519.PublicKey, []ed25519.PrivateKey) {
	t.Helper()
	var pubs []ed25519.PublicKey
	var privs []ed25519.PrivateKey
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pubs = append(pubs, pub)
		privs = append(privs, priv)
	}
	return pubs, privs
}

func signersOf(privs ...ed25519.PrivateKey) []crypto.Signer {
	out := make([]crypto.Signer, 0, len(privs))
	for _, p := range privs {
		out = append(out, p)
	}
	return out
}

// aCeremony is a network that should work: 2-of-3 roots, one signer, one
// witness, one log.
func aCeremony(t *testing.T) (Ceremony, []ed25519.PrivateKey) {
	t.Helper()
	roots, rootPrivs := keys(t, 3)
	signers, _ := keys(t, 1)
	logPub, _ := keys(t, 1)
	witnessPub, _ := keys(t, 1)

	return Ceremony{
		Name:      "norn-lab",
		Roots:     roots,
		RootThr:   2,
		Signers:   signers,
		SignerThr: 1,
		LogKey:    logPub[0],
		LogURLs:   []string{"https://log.example/lab"},
		Witnesses: []Witness{{Name: "pi", Key: witnessPub[0], URL: "http://10.0.0.153:8100"}},
		TS:        1_760_000_000,
	}, rootPrivs
}

func TestBuildProducesAGenesisThatReplays(t *testing.T) {
	ceremony, rootPrivs := aCeremony(t)

	got, err := Build(ceremony, signersOf(rootPrivs[0], rootPrivs[1]))
	if err != nil {
		t.Fatal(err)
	}

	// The strongest check available: replay the entry it just produced under
	// the anchor it just produced. A ceremony whose output does not replay has
	// created a network nobody can join.
	st := replay.Replay(replay.FromTrust(got.Trust),
		[][]byte{got.Entry})
	if len(st.Rejected) != 0 {
		t.Fatalf("the genesis it built does not replay: %+v", st.Rejected)
	}
	if st.RootThr != 2 || st.SignerThr != 1 {
		t.Errorf("thresholds = %d/%d", st.RootThr, st.SignerThr)
	}
	if len(st.Roots) != 3 || len(st.Signers) != 1 {
		t.Errorf("roots = %d, signers = %d", len(st.Roots), len(st.Signers))
	}

	// And the trust file it wrote is a usable anchor.
	if err := got.Trust.Validate(); err != nil {
		t.Fatalf("the trust file is not usable: %v", err)
	}
	if got.Trust.Origin != mustOrigin(t, got.Trust.Net) {
		t.Error("origin does not derive from net")
	}
	if got.Fingerprint == "" || !strings.Contains(got.Fingerprint, "-") {
		t.Errorf("fingerprint = %q", got.Fingerprint)
	}

	// The log key must be named for this network, or no checkpoint it signs
	// will ever verify here (§9.1).
	verifier, err := note.ParseVerifierKey(got.Trust.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.Name != got.Trust.Origin {
		t.Errorf("log key is named %q, want the origin", verifier.Name)
	}
}

func TestTheNetIsFreshEachTime(t *testing.T) {
	ceremony, rootPrivs := aCeremony(t)
	first, err := Build(ceremony, signersOf(rootPrivs[0], rootPrivs[1]))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(ceremony, signersOf(rootPrivs[0], rootPrivs[1]))
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Trust.Net) == string(second.Trust.Net) {
		t.Fatal("two ceremonies produced the same network id")
	}
	if first.Fingerprint == second.Fingerprint {
		t.Fatal("two networks share a fingerprint")
	}
}

func TestAGivenNetIsUsed(t *testing.T) {
	ceremony, rootPrivs := aCeremony(t)
	ceremony.Net = []byte("sixteen bytes!!!")
	got, err := Build(ceremony, signersOf(rootPrivs[0], rootPrivs[1]))
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Trust.Net) != "sixteen bytes!!!" {
		t.Errorf("net = %q", got.Trust.Net)
	}
}

// Genesis needs root_thr roots. One signature short is a network whose own
// first entry would be refused, so it is refused here instead.
func TestTooFewRootSignatures(t *testing.T) {
	ceremony, rootPrivs := aCeremony(t)
	_, err := Build(ceremony, signersOf(rootPrivs[0]))
	if err == nil {
		t.Fatal("built a genesis with one signature and root_thr 2")
	}
	if !strings.Contains(err.Error(), "root_thr") {
		t.Errorf("the error should name the threshold: %v", err)
	}
}

// A key that is not a root cannot authorise the ceremony, however many of them
// there are.
func TestASignatureByANonRoot(t *testing.T) {
	ceremony, rootPrivs := aCeremony(t)
	_, stranger := keys(t, 1)
	_, err := Build(ceremony, signersOf(rootPrivs[0], stranger[0]))
	if err == nil {
		t.Fatal("counted a stranger's signature towards root_thr")
	}
	if !strings.Contains(err.Error(), "not a root") {
		t.Errorf("the error should say whose signature it refused: %v", err)
	}
}

func TestCeremoniesThatCouldNotWork(t *testing.T) {
	base, rootPrivs := aCeremony(t)
	someKey := base.Roots[0]

	cases := []struct {
		why    string
		mutate func(*Ceremony)
		says   string
	}{
		{"no name", func(c *Ceremony) { c.Name = "" }, "name"},
		{"a name over 64 bytes", func(c *Ceremony) { c.Name = strings.Repeat("n", 65) }, "name"},
		{"no roots", func(c *Ceremony) { c.Roots = nil }, "root"},
		{"no signers", func(c *Ceremony) { c.Signers = nil }, "signer"},
		{"root_thr of zero", func(c *Ceremony) { c.RootThr = 0 }, "root_thr"},
		{"root_thr above the set", func(c *Ceremony) { c.RootThr = 4 }, "root_thr"},
		{"signer_thr above the set", func(c *Ceremony) { c.SignerThr = 2 }, "signer_thr"},
		{"a duplicated root", func(c *Ceremony) { c.Roots = append(c.Roots, c.Roots[0]) }, "twice"},
		{"a key in both roles", func(c *Ceremony) { c.Signers = append(c.Signers, someKey) }, "both"},
		{"no witnesses", func(c *Ceremony) { c.Witnesses = nil }, "witness"},
		{"two witnesses of one name", func(c *Ceremony) {
			c.Witnesses = append(c.Witnesses, c.Witnesses[0])
		}, "name"},
		{"no log URL", func(c *Ceremony) { c.LogURLs = nil }, "log"},
		{"no log key", func(c *Ceremony) { c.LogKey = nil }, "log key"},
		{"a net of the wrong length", func(c *Ceremony) { c.Net = []byte("short") }, "16 bytes"},
		{"a quorum larger than the witness set", func(c *Ceremony) { c.PolicyQuorum = 2 }, "quorum"},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			ceremony := base
			ceremony.Roots = append([]ed25519.PublicKey{}, base.Roots...)
			ceremony.Signers = append([]ed25519.PublicKey{}, base.Signers...)
			ceremony.Witnesses = append([]Witness{}, base.Witnesses...)
			ceremony.LogURLs = append([]string{}, base.LogURLs...)
			c.mutate(&ceremony)

			if _, err := Build(ceremony, signersOf(rootPrivs[0], rootPrivs[1])); err == nil {
				t.Fatalf("built a network with %s", c.why)
			} else if !strings.Contains(err.Error(), c.says) {
				t.Errorf("error = %v, want something about %q", err, c.says)
			}
		})
	}
}

// The generated policy has to name the witnesses it depends on, or the quorum
// is a promise about parties the file never identifies.
func TestTheGeneratedPolicyNamesItsWitnesses(t *testing.T) {
	ceremony, rootPrivs := aCeremony(t)
	extra, _ := keys(t, 1)
	ceremony.Witnesses = append(ceremony.Witnesses,
		Witness{Name: "vps", Key: extra[0], URL: "https://witness.example"})
	ceremony.PolicyQuorum = 2

	got, err := Build(ceremony, signersOf(rootPrivs[0], rootPrivs[1]))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"witness pi ", "witness vps ", "quorum", "log "} {
		if !strings.Contains(got.Trust.Policy, want) {
			t.Errorf("the policy omits %q:\n%s", want, got.Trust.Policy)
		}
	}
	if !strings.Contains(got.Trust.Policy, " 2 ") {
		t.Errorf("the quorum size is not in the policy:\n%s", got.Trust.Policy)
	}
}

func TestAGivenPolicyIsUsedVerbatim(t *testing.T) {
	ceremony, rootPrivs := aCeremony(t)
	// A hand-written policy still has to be a usable one: it must name the
	// same witnesses the trust file lists, with the same keys (§9.1). What
	// makes this "verbatim" is the wording -- a group named by its owner
	// rather than the generator's -- not a licence to be inconsistent.
	witnessKey := note.CosignerVerifierKey("norn-witness/pi", ceremony.Witnesses[0].Key)
	ceremony.Policy = "witness pi " + witnessKey + "\ngroup mine any pi\nquorum mine\n"

	got, err := Build(ceremony, signersOf(rootPrivs[0], rootPrivs[1]))
	if err != nil {
		t.Fatal(err)
	}
	if got.Trust.Policy != ceremony.Policy {
		t.Errorf("policy = %q, want the one given", got.Trust.Policy)
	}
	if strings.Contains(got.Trust.Policy, "group all") {
		t.Error("the generated policy overwrote the one supplied")
	}
}

// A supplied policy that does not agree with the witnesses is refused, because
// the generator cannot know which of the two the operator meant.
func TestAnInconsistentPolicyIsRefused(t *testing.T) {
	ceremony, rootPrivs := aCeremony(t)
	witnessKey := note.CosignerVerifierKey("norn-witness/pi", ceremony.Witnesses[0].Key)
	ceremony.Policy = "witness elsewhere " + witnessKey + "\nquorum elsewhere\n"

	if _, err := Build(ceremony, signersOf(rootPrivs[0], rootPrivs[1])); err == nil {
		t.Fatal("built a network whose policy names a witness it does not have")
	}
}

// Params are optional; when given they must survive into the replayed state,
// because a network that cannot set its own checkpoint interval at genesis has
// to govern it later with an entry nobody has signed yet.
func TestParamsReachTheState(t *testing.T) {
	ceremony, rootPrivs := aCeremony(t)
	ceremony.Params = map[string]any{"mmd": uint64(45)}
	got, err := Build(ceremony, signersOf(rootPrivs[0], rootPrivs[1]))
	if err != nil {
		t.Fatal(err)
	}
	st := replay.Replay(replay.FromTrust(got.Trust),
		[][]byte{got.Entry})
	if st.Params["mmd"] != uint64(45) {
		t.Errorf("mmd = %v, want 45", st.Params["mmd"])
	}
}

func TestTheEntryIsAGenesisEntry(t *testing.T) {
	ceremony, rootPrivs := aCeremony(t)
	got, err := Build(ceremony, signersOf(rootPrivs[0], rootPrivs[1]))
	if err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(got.Entry)
	if err != nil {
		t.Fatal(err)
	}
	if env.T != "genesis" {
		t.Errorf("t = %q", env.T)
	}
	if env.After != nil {
		t.Error("genesis is entry 0; an `after` guard on it means nothing")
	}
	if len(env.Sigs) != 2 {
		t.Errorf("%d signatures", len(env.Sigs))
	}
	if string(got.Trust.GenesisHash) != string(entry.LeafHash(got.Entry)) {
		t.Error("genesis_hash is not the leaf hash of the entry (§9.1)")
	}
}

func mustOrigin(t *testing.T, net []byte) string {
	t.Helper()
	origin, err := trust.OriginFor(net)
	if err != nil {
		t.Fatal(err)
	}
	return origin
}
