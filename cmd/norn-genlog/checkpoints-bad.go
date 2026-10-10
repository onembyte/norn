// These vectors write the checkpoints-bad directory.

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
)

// paddedSizeLine re-signs the checkpoint over a body whose size line carries a
// leading zero, so the signature is valid and only the canonical-decimal rule
// can refuse it.
func paddedSizeLine(base, origin string, key ed25519.PrivateKey,
	signers []cosignpkg.Signer) (string, error) {

	body, err := noteBody(base)
	if err != nil {
		return "", err
	}
	lines := strings.SplitN(body, "\n", 3)
	if len(lines) < 3 {
		return "", fmt.Errorf("a checkpoint body has three lines, this has %d", len(lines))
	}
	lines[1] = "0" + lines[1]
	signed, err := note.Sign(strings.Join(lines, "\n"), origin, key)
	if err != nil {
		return "", err
	}
	return staggeredCosigner(signers)(signed)
}

// rewriteBodyOrigin replaces the checkpoint body's first line and re-signs,
// leaving the note name and everything else exactly as it was. The note still
// verifies under this network's key, so only §10's origin comparison can
// refuse the result.
func rewriteBodyOrigin(base, noteName, bodyOrigin string, key ed25519.PrivateKey,
	signers []cosignpkg.Signer) (string, error) {

	body, err := noteBody(base)
	if err != nil {
		return "", err
	}
	_, rest, found := strings.Cut(body, "\n")
	if !found {
		return "", fmt.Errorf("a checkpoint body has three lines")
	}
	signed, err := note.Sign(bodyOrigin+"\n"+rest, noteName, key)
	if err != nil {
		return "", err
	}
	return staggeredCosigner(signers)(signed)
}

// caseFlipped upper-cases the first letter of the origin's base32 tail, which
// §2 defines as lowercase. The string is otherwise byte-identical.
func caseFlipped(origin string) string {
	for i := 0; i < len(origin); i++ {
		if origin[i] >= 'a' && origin[i] <= 'z' && i > strings.Index(origin, "/") {
			return origin[:i] + string(origin[i]-32) + origin[i+1:]
		}
	}
	return origin
}

// shortRootLine re-encodes the root with one byte appended -- 33 bytes, whose
// first 32 are the honest root -- then re-signs and re-cosigns the body. The
// note is impeccable and the tree still matches for anyone who reads 32 bytes
// and stops; §6's "32 bytes once decoded" is the only rule that refuses it.
func shortRootLine(base, origin string, key ed25519.PrivateKey,
	signers []cosignpkg.Signer) (string, error) {

	body, err := noteBody(base)
	if err != nil {
		return "", err
	}
	lines := strings.SplitN(body, "\n", 3)
	if len(lines) < 3 {
		return "", fmt.Errorf("a checkpoint body has three lines, this has %d", len(lines))
	}
	// The third element carries the body's own terminating newline; §7 makes
	// that newline part of the note, so it has to survive the substitution.
	tail := strings.TrimRight(lines[2], "\n")
	root, err := base64.StdEncoding.DecodeString(tail)
	if err != nil {
		return "", fmt.Errorf("the root line is not base64: %w", err)
	}
	if len(root) != sha256.Size {
		return "", fmt.Errorf("the honest root is %d bytes, not %d", len(root), sha256.Size)
	}
	// A *longer* line, whose first 32 bytes are the honest root. Dropping a
	// byte instead would be caught by the rebuild below -- the truncated value
	// is not the tree's head -- so the length rule would be refused-but-not-
	// pinned. With a trailing byte, a reader that takes the first 32 and reads
	// on gets the right root, matches the tree, and accepts a checkpoint whose
	// root line is not a SHA-256 hash. Only the length says so.
	lines[2] = base64.StdEncoding.EncodeToString(append(root, 0x00)) +
		lines[2][len(tail):]
	signed, err := note.Sign(strings.Join(lines, "\n"), origin, key)
	if err != nil {
		return "", err
	}
	return staggeredCosigner(signers)(signed)
}

// rewriteLastSignature applies f to the final `— …` line of a signed note.
// The text and every earlier line are untouched, so the rewritten line is the
// only thing a reader can object to.
func rewriteLastSignature(signed string, f func(string) string) string {
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], note.SigPrefix) {
			lines[i] = f(lines[i])
			break
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// raiseCosignatureScalar changes only S of a listed witness's honest line.
// Adding L preserves its scalar residue but violates §3.1's one encoding rule.
func raiseCosignatureScalar(signed string) (string, error) {
	var mutationErr error
	out := rewriteLastSignature(signed, func(line string) string {
		name, blob, ok := strings.Cut(strings.TrimPrefix(line, note.SigPrefix), " ")
		payload, err := base64.StdEncoding.DecodeString(blob)
		if !ok || err != nil || len(payload) != 76 || !strings.HasPrefix(name, "norn-witness/") {
			mutationErr = fmt.Errorf("expected a witness cosignature, got %q", name)
			return line
		}
		l, err := hex.DecodeString("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
		if err != nil {
			mutationErr = err
			return line
		}
		carry := uint16(0)
		for i := 0; i < 32; i++ {
			sum := uint16(payload[44+i]) + uint16(l[i]) + carry
			payload[44+i], carry = byte(sum), sum>>8
		}
		return note.SigPrefix + name + " " + base64.StdEncoding.EncodeToString(payload)
	})
	return out, mutationErr
}

// logSignatureLast moves the log's own signature line to the end of the block,
// so `rewriteLastSignature` can reach it. §10 says the log's line may appear
// anywhere and order carries nothing, so this changes no rule.
func logSignatureLast(signed, origin string) string {
	text, block, _ := strings.Cut(signed, "\n\n")
	var others, logLines []string
	for _, line := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
		if strings.HasPrefix(line, note.SigPrefix+origin+" ") {
			logLines = append(logLines, line)
		} else {
			others = append(others, line)
		}
	}
	all := append(others, logLines...)
	return text + "\n\n" + strings.Join(all, "\n") + "\n"
}

// nameWithSpace puts a space inside the key name. Splitting the line at its
// first space then leaves a payload that is not base64.
func nameWithSpace(line string) string {
	rest := strings.TrimPrefix(line, note.SigPrefix)
	name, blob, _ := strings.Cut(rest, " ")
	return note.SigPrefix + name + " extra " + blob
}

// dropPadding re-encodes the payload without its `=`.
func dropPadding(line string) string {
	rest := strings.TrimPrefix(line, note.SigPrefix)
	name, blob, _ := strings.Cut(rest, " ")
	return note.SigPrefix + name + " " + strings.TrimRight(blob, "=")
}

// nonzeroPadBits changes only the unused low bits of the last base64 data
// character. A permissive decoder gets the same bytes; RFC 4648 §3.5 refuses
// the alternate spelling.
func nonzeroPadBits(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded {
		return "", fmt.Errorf("input is not canonical padded base64")
	}
	padding := len(encoded) - len(strings.TrimRight(encoded, "="))
	if padding == 0 {
		return "", fmt.Errorf("base64 input has no unused pad bits")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	position := len(encoded) - padding - 1
	value := strings.IndexByte(alphabet, encoded[position])
	if value < 0 {
		return "", fmt.Errorf("base64 final data character is invalid")
	}
	mask := (1 << (padding * 2)) - 1
	mutated := []byte(encoded)
	mutated[position] = alphabet[(value&^mask)|1]
	return string(mutated), nil
}

func rewriteSignaturePadBits(signed, whose string) (string, error) {
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	prefix := note.SigPrefix + whose + " "
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.HasPrefix(lines[i], prefix) {
			continue
		}
		blob := strings.TrimPrefix(lines[i], prefix)
		bad, err := nonzeroPadBits(blob)
		if err != nil {
			return "", err
		}
		lines[i] = prefix + bad
		return strings.Join(lines, "\n") + "\n", nil
	}
	return "", fmt.Errorf("no signature line for %q", whose)
}

// appendByte adds one byte to the decoded payload, so it is 69 bytes where §7
// says 68 and a prefix-reading verifier sees no difference.
func appendByte(line string) string {
	rest := strings.TrimPrefix(line, note.SigPrefix)
	name, blob, _ := strings.Cut(rest, " ")
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return line
	}
	return note.SigPrefix + name + " " +
		base64.StdEncoding.EncodeToString(append(raw, 0x00))
}

// appendForgedLogSignature adds a second line under the log's own key that does
// not verify. Both name the log; a reader that takes the first valid one and
// stops never looks at the other.
func appendForgedLogSignature(signed, origin string) (string, error) {
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, note.SigPrefix+origin+" ") {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(
			strings.TrimPrefix(line, note.SigPrefix+origin+" "))
		if err != nil {
			return "", err
		}
		forged := append([]byte(nil), payload...)
		forged[len(forged)-1] ^= 0x01
		return strings.Join(lines, "\n") + "\n" +
			note.SignatureLine(origin, forged) + "\n", nil
	}
	return "", fmt.Errorf("no log signature line for %q", origin)
}

// appendForgedSecondLine gives one witness a second cosignature line: newer
// than its first, and not verifying. Everything else about the checkpoint is
// correct, so only a per-line reading of §10 can refuse it.
func appendForgedSecondLine(signed, whose string) (string, error) {
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "— "+whose+" ") {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(
			strings.TrimPrefix(line, "— "+whose+" "))
		if err != nil {
			return "", err
		}
		second := append([]byte(nil), payload...)
		// 4 bytes of key id, then a big-endian uint64 timestamp: one second
		// later, so a reader selecting the newest line selects this one.
		at := binary.BigEndian.Uint64(second[4:12])
		binary.BigEndian.PutUint64(second[4:12], at+1)
		second[len(second)-1] ^= 0x01
		return strings.Join(lines, "\n") + "\n" +
			note.SignatureLine(whose, second) + "\n", nil
	}
	return "", fmt.Errorf("no signature line for %q", whose)
}

// --- checkpoints-bad: the note layer's negatives (cold gate run 5, G2) ----
//
// §12.1 claimed these refusals for §6 and §10. Every one of them was a Go
// test in this repository and none of them was a file, so a second
// implementer received a suite of entirely valid notes: run 5 built a verifier
// that never checked a note or cosignature signature and passed all 597
// checks. A rule nobody can fail is a rule nobody has to implement.
//
// Each file is served in place of `served/checkpoint`, over the honest tiles,
// under the shipped `trust.cbor`. Everything else about the log is correct, so
// a refusal can only come from the checkpoint.
type badCheckpoint struct {
	Name   string
	Reason string
	Signed string
}

// forgeLastSignature flips a bit inside the newest signature line's payload,
// leaving its key id and any timestamp intact. The line stays syntactically
// perfect and stops verifying, which is the only construction that separates a
// verifier from one that pretends.
func forgeLastSignature(signed, whose string) (string, error) {
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.HasPrefix(lines[i], "— "+whose+" ") {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(
			strings.TrimPrefix(lines[i], "— "+whose+" "))
		if err != nil {
			return "", err
		}
		// The last byte is signature, never key id (4 bytes) or timestamp.
		payload[len(payload)-1] ^= 0x01
		lines[i] = note.SignatureLine(whose, payload)
		return strings.Join(lines, "\n") + "\n", nil
	}
	return "", fmt.Errorf("no signature line for %q", whose)
}

func buildBadCheckpoints(root, origin string, key ed25519.PrivateKey,
	signed string, signers []cosignpkg.Signer) ([]badCheckpoint, error) {

	body, err := noteBody(signed)
	if err != nil {
		return nil, err
	}
	// Re-signing the body must reproduce the log's own line: Ed25519 is
	// deterministic, and if it does not, every negative below is built over a
	// checkpoint that is not the one the suite serves.
	base, err := note.Sign(body, origin, key)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(signed, base) {
		return nil, fmt.Errorf("re-signing the checkpoint body did not reproduce the served signature")
	}
	stranger, err := seedKey(root, "stranger")
	if err != nil {
		return nil, err
	}
	cosignWith := func(base string, chosen ...cosignpkg.Signer) (string, error) {
		return staggeredCosigner(chosen)(base)
	}

	byName := map[string]cosignpkg.Signer{}
	for _, s := range signers {
		byName[s.Name] = s
	}

	var out []badCheckpoint

	out = append(out, badCheckpoint{"01-unsigned",
		"the checkpoint body with no signature line at all: nothing vouches for this tree",
		body + "\n"})

	wrongKey, err := note.Sign(body, origin, stranger)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"02-wrong-log-key",
		"signed under the log's own name by a key the anchor does not pin", wrongKey})

	elsewhere := "norn/elsewhere"
	otherBody := elsewhere + body[strings.Index(body, "\n"):]
	otherLog, err := note.Sign(otherBody, elsewhere, key)
	if err != nil {
		return nil, err
	}
	otherLog, err = cosignWith(otherLog, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"03-wrong-origin",
		"a perfectly valid checkpoint for another log: right key, wrong network", otherLog})

	forged, err := forgeLastSignature(base, origin)
	if err != nil {
		return nil, err
	}
	forged, err = cosignWith(forged, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"04-forged-log-signature",
		"the log's signature line is the right shape and the right key id, and does not verify", forged})

	short, err := cosignWith(base, byName["norn-witness/pi"])
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"05-one-cosignature-short",
		"one witness of the two the policy requires", short})

	out = append(out, badCheckpoint{"06-no-cosignatures",
		"signed by the log and cosigned by nobody", base})

	unnamed, err := cosignWith(base, cosignpkg.Signer{Name: "norn-witness/stranger", Key: stranger})
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"07-unnamed-witness-only",
		"cosigned only by a witness the policy never names, which counts for nothing", unnamed})

	forgedCosig, err := cosignWith(base, byName["norn-witness/pi"], byName["norn-witness/vps"])
	if err != nil {
		return nil, err
	}
	forgedCosig, err = forgeLastSignature(forgedCosig, "norn-witness/vps")
	if err != nil {
		return nil, err
	}
	// §6 fixes a checkpoint at three lines: origin, size, root, and **no
	// extension lines**. The rule was enforced and unvectored, so a second
	// implementer could accept a fourth line and pass everything shipped.
	// Signed and cosigned properly, so only the rule can refuse it.
	extended, err := note.Sign(body+"norn extension line\n", origin, key)
	if err != nil {
		return nil, err
	}
	extended, err = cosignWith(extended, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"09-extension-line",
		"a fourth body line, signed and cosigned exactly as correctly as the real one: " +
			"§6 allows origin, size and root and nothing else", extended})

	// H8: the origin line says which log a checkpoint is about, and the note
	// name and key id bind only the *signer*. This one is signed by the right
	// key under the right name, and claims to be another network's head.
	wrongBody := elsewhere + body[strings.Index(body, "\n"):]
	wrongOrigin, err := note.Sign(wrongBody, origin, key)
	if err != nil {
		return nil, err
	}
	wrongOrigin, err = cosignWith(wrongOrigin, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"10-wrong-body-origin",
		"signed by this network's log key, under this network's name, and its origin " +
			"line names another log", wrongOrigin})

	// `skip-cosig-verify`: all three named witnesses sign, two of them verify.
	// A reader that merely declines to count the bad line still has its quorum
	// of two and carries on; §10 says the checkpoint is refused. `08` cannot
	// tell those apart, because one valid line falls short either way.
	allThree, err := cosignWith(base, byName["norn-witness/pi"],
		byName["norn-witness/vps"], byName["norn-witness/friend"])
	if err != nil {
		return nil, err
	}
	withQuorum, err := forgeLastSignature(allThree, "norn-witness/friend")
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"11-forged-cosignature-with-quorum",
		"three named witnesses, two of whose cosignatures verify: the quorum is met " +
			"without the third, and §10 refuses the checkpoint anyway", withQuorum})

	// `cosig-all-lines`: §10 says "every cosignature by a witness the policy
	// names must verify"; §5.3 says two verifying lines from one witness are
	// its newest. Neither settled the case where one witness supplies both, so
	// a reader picking each witness's newest *verifying* line saw three good
	// witnesses and carried on. `11` is the neighbouring case and cannot stand
	// in for it: there the bad line's witness has no good line, so declining
	// to count it still leaves a quorum of two.
	secondLine, err := appendForgedSecondLine(allThree, "norn-witness/friend")
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"12-second-line-from-one-witness",
		"all three witnesses cosign and verify, and `friend` carries a second, newer " +
			"line that does not: a reader taking each witness's newest verifying line " +
			"sees a full quorum, and §10 refuses the checkpoint anyway", secondLine})

	// Cold gate run 8, D21: four framing rules §7 states, both
	// implementations enforce, and no file exercised. An ASCII hyphen instead
	// of U+2014 is what a reader writes who never looks at the bytes.
	out = append(out, badCheckpoint{"13-ascii-dash-signature",
		"the log's signature line opens with an ASCII hyphen instead of §7's em dash",
		strings.Replace(allThree, "\n"+note.SigPrefix, "\n- ", 1)})

	out = append(out, badCheckpoint{"14-unterminated-signature-block",
		"the last signature line does not end in a newline, so the block is unterminated",
		strings.TrimRight(allThree, "\n")})

	// A size line with a leading zero: two readers that parse it differently
	// disagree about which tree they are looking at.
	zeroPadded, err := paddedSizeLine(base, origin, key, signers)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"15-size-leading-zero",
		"the size line carries a leading zero, which is not canonical decimal", zeroPadded})

	// Two signature lines under the log's key, one of which does not verify.
	// The same shape as §10's per-line cosignature rule, on the log itself.
	twice, err := appendForgedLogSignature(allThree, origin)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"16-two-log-signatures",
		"two signature lines name the log's key and one does not verify: a reader " +
			"that stops at the first valid one accepts a checkpoint carrying a forgery",
		twice})

	// Cold gate run 10, D11. §6 bounds the root line at 32 bytes once decoded
	// and no file carried another length, so the only rule that ever looked at
	// that line was the rebuild-and-compare below it. Signed and cosigned
	// exactly as correctly as the real one, so the length is the whole fault.
	shortRoot, err := shortRootLine(base, origin, key, signers)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"17-root-wrong-length",
		"the root line decodes to 33 bytes whose first 32 are the honest root: a " +
			"reader that takes the first 32 and reads on matches the rebuilt tree " +
			"and accepts it, so §6's length is the only rule that can refuse it",
		shortRoot})

	// Cold gate run 10, D13. §7's framing left five splits to the reader and
	// three of them can be separated by a file. Each of these is `allThree`
	// with its **last** signature line rewritten one way, so the line is a
	// perfectly good signature under the lax reading and malformed under this
	// document's.
	out = append(out, badCheckpoint{"18-signature-name-with-space",
		"a signature line whose name carries a space: split at the first space the " +
			"payload is not base64, split at the last it is a signature from a name " +
			"nobody lists, which §10 ignores rather than refuses",
		rewriteLastSignature(allThree, nameWithSpace)})

	out = append(out, badCheckpoint{"19-signature-unpadded-base64",
		"the last signature line's payload is unpadded base64: the same bytes to a " +
			"raw-base64 reader, and not §7's encoding",
		rewriteLastSignature(allThree, dropPadding)})

	out = append(out, badCheckpoint{"20-signature-payload-too-long",
		"one byte appended to the log's 68-byte payload: a verifier that reads the " +
			"first 68 and stops verifies it, so this head has unboundedly many " +
			"byte-distinct forms that are all valid. The framing takes it, as it " +
			"would a stranger's line of any length; the log's key refuses it (D-074 c)",
		rewriteLastSignature(logSignatureLast(allThree, origin), appendByte)})

	// Cold gate run 11, D7. §10's `require cp.origin == norn.trust.origin` was
	// separated from neither a prefix match nor a case-folded one: every origin
	// negative used an UNRELATED origin, so none of them is a prefix or a case
	// variant of this network's. §10 argues at length that the cosignature
	// match must be name AND key id because a name-only match hands anyone a
	// veto; this is the same argument from the other side, where a loose match
	// hands an attacker an acceptance.
	suffixed, err := rewriteBodyOrigin(base, origin, origin+"a", key, signers)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"21-origin-with-a-suffix",
		"the origin line is this network's origin plus one base32 character, " +
			"signed and cosigned exactly as correctly as the real head: a reader " +
			"matching on a prefix accepts it", suffixed})

	folded, err := rewriteBodyOrigin(base, origin, caseFlipped(origin), key, signers)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"22-origin-case-changed",
		"the same origin with one character in the other case: a reader folding " +
			"case accepts it, and §2's origin is lowercase base32 by construction",
		folded})

	// D14b. The final signature line already has its required LF. A second
	// one creates an empty line and is malformed note framing, not a terminator
	// that a parser may trim away.
	out = append(out, badCheckpoint{"23-extra-final-newline",
		"the final signature line ends in one LF and an extra LF adds a forbidden blank line",
		allThree + "\n"})

	// D14c. Framing permits both supported payload sizes before a key is
	// matched. Once name and key ID identify the trusted 0x01 log key, however,
	// a 76-byte payload cannot be its signature and must fail at log-signature.
	logVerifier, err := note.ParseVerifierKey(note.VerifierKey(origin,
		key.Public().(ed25519.PublicKey)))
	if err != nil {
		return nil, err
	}
	otherLength := append(append([]byte(nil), logVerifier.ID()...), make([]byte, 8+64)...)
	out = append(out, badCheckpoint{"24-log-key-other-algorithm-length",
		"a 76-byte payload under the log key's name and key ID is a log-signature failure, even beside its valid line",
		allThree + note.SignatureLine(logVerifier.Name, otherLength) + "\n"})

	// SEC-027, the same rule on the witness side. A 68-byte payload -- a note
	// signature's length -- under a listed witness's name and cosignature key
	// ID cannot be that witness's line. A reader that skips it as "not a
	// cosignature" still has three good lines and accepts the head; §7 and
	// §10.1 refuse it as `cosignature`.
	pi := byName["norn-witness/pi"]
	piID := note.KeyIDFor(pi.Name, pi.Key.Public().(ed25519.PublicKey), note.AlgCosignature)
	noteLength := append(append([]byte(nil), piID...), make([]byte, ed25519.SignatureSize)...)
	out = append(out, badCheckpoint{"28-witness-key-other-algorithm-length",
		"a 68-byte payload under a listed witness's name and cosignature key ID is a cosignature failure, even beside its valid line",
		allThree + note.SignatureLine(pi.Name, noteLength) + "\n"})

	// D14a. These mutations preserve the decoded bytes and every signature,
	// so the refusal belongs to canonical encoding rather than verification.
	badLogPayload, err := rewriteSignaturePadBits(allThree, origin)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"25-signature-nonzero-pad-bits",
		"the log signature payload has nonzero unused base64 pad bits but decodes to the same valid signature",
		badLogPayload})
	badCosignature, err := rewriteSignaturePadBits(allThree, "norn-witness/friend")
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"26-cosignature-nonzero-pad-bits",
		"a witness cosignature payload has nonzero unused base64 pad bits but decodes to the same valid cosignature",
		badCosignature})
	rootLines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	badRootEncoding, err := nonzeroPadBits(rootLines[2])
	if err != nil {
		return nil, err
	}
	rootLines[2] = badRootEncoding
	badRootBody := strings.Join(rootLines, "\n") + "\n"
	badRoot, err := note.Sign(badRootBody, origin, key)
	if err != nil {
		return nil, err
	}
	badRoot, err = cosignWith(badRoot, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"27-root-nonzero-pad-bits",
		"the root line has nonzero unused base64 pad bits but decodes to the same signed tree root",
		badRoot})

	// Cold gate run 13, D18: the root with its `=` dropped. A lenient decoder
	// reads the same 32 bytes; §6 says padded. Re-signed and re-cosigned, so
	// only the body's encoding can refuse it.
	rootLines = strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if !strings.HasSuffix(rootLines[2], "=") {
		return nil, fmt.Errorf("the served root %q carries no padding to drop", rootLines[2])
	}
	rootLines[2] = strings.TrimRight(rootLines[2], "=")
	unpadded, err := note.Sign(strings.Join(rootLines, "\n")+"\n", origin, key)
	if err != nil {
		return nil, err
	}
	unpadded, err = cosignWith(unpadded, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"29-root-unpadded",
		"the root line drops its padding: a lenient decoder reads the same 32 bytes, and §6 requires the padded form",
		unpadded})

	// Cold gate run 13, D4: §10.1 step 3 before step 4. A body with a
	// non-canonical size, signed under the log's name by a key the anchor
	// does not pin: `log-signature`, not `checkpoint`. Every other body fault
	// in this directory is signed by the log, so a reader that parses the
	// body before checking the signature refused each for the same reason.
	sizeLines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	sizeLines[1] = "0" + sizeLines[1]
	bodyAndKey, err := note.Sign(strings.Join(sizeLines, "\n")+"\n", origin, stranger)
	if err != nil {
		return nil, err
	}
	bodyAndKey, err = cosignWith(bodyAndKey, signers...)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"30-noncanonical-size-under-untrusted-signer",
		"a leading-zero size, signed by a key the anchor does not pin: the signature step comes first",
		bodyAndKey})

	out = append(out, badCheckpoint{"08-forged-cosignature",
		"two cosignature lines, both naming witnesses the policy lists, one of which does not verify: " +
			"the quorum is met only by a verifier that does not check them", forgedCosig})

	raised, err := raiseCosignatureScalar(signed)
	if err != nil {
		return nil, err
	}
	out = append(out, badCheckpoint{"31-cosignature-S-plus-L",
		"a listed witness's honest cosignature with S + L: everything but the scalar encoding is valid", raised})

	return out, nil
}

func writeBadCheckpoints(root, origin string, key ed25519.PrivateKey,
	signed string, signers []cosignpkg.Signer) error {

	cases, err := buildBadCheckpoints(root, origin, key, signed, signers)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "checkpoints-bad")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(cases))
	reasons := map[string]string{}
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(dir, c.Name+".checkpoint"), []byte(c.Signed), 0o644); err != nil {
			return err
		}
		names = append(names, c.Name)
		reasons[c.Name] = c.Reason
	}
	// Cold gate run 8, D6. The comment used to say "04 and 08 are the two a
	// signature-blind verifier accepts". That stopped being true when `11` was
	// added and again when `12` was: every one of these four is a checkpoint
	// whose ONLY defect is a signature of the right shape that does not
	// verify, so a reader that never calls Ed25519 accepts all four. Listed
	// rather than described, and checked below, because a sentence counting
	// files is a sentence that goes stale.
	blind := []string{
		"04-forged-log-signature",
		"08-forged-cosignature",
		"11-forged-cosignature-with-quorum",
		"12-second-line-from-one-witness",
		// Cold gate run 9, D6: this list is generated and its contents were
		// hand-written, so adding `16` silently falsified the claim that these
		// are the set "and nothing else here". `16`'s only defect is a second
		// log signature that does not verify, which a reader that never calls
		// Ed25519 cannot see. The set is now *computed* from the shipped files
		// by `TestTheSignatureBlindSetIsComputedNotAsserted`; this list is
		// checked against that computation rather than trusted.
		"16-two-log-signatures",
		"31-cosignature-S-plus-L",
	}
	for _, want := range blind {
		if _, ok := reasons[want]; !ok {
			return fmt.Errorf("signature-blind list names %q, which is not a case", want)
		}
	}
	// Cold gate run 10. Every negative names the section that states the rule
	// it is about, and a phrase that must appear there. Without this a rule
	// can live in §12.1's coverage table and nowhere a reader will look --
	// which is how §7's terminating newline, §6's canonical size line and
	// §10's every-line rule all reached a gate unstated.
	rules := map[string]map[string]string{
		"31-cosignature-S-plus-L": {"section": "10", "says": "must verify"},
		// 6.5l-vi-b-ii-d: these two cited a rule a later step states. 01 has
		// no signature line, so §7's framing refuses it before any signature
		// is looked for; 03 is signed under another origin's name, so the
		// signature refuses it before its origin is read. `codes` below made
		// the disagreement visible, and specdoc now holds the two together.
		"01-unsigned":                                 {"section": "7", "says": "carries **at least one signature line**"},
		"02-wrong-log-key":                            {"section": "10", "says": "norn.trust.log_key"},
		"03-wrong-origin":                             {"section": "10", "says": "whatever origin it names"},
		"04-forged-log-signature":                     {"section": "10", "says": "MUST\n  # verify"},
		"05-one-cosignature-short":                    {"section": "10", "says": "the quorum must be satisfied"},
		"06-no-cosignatures":                          {"section": "10", "says": "the quorum must be satisfied"},
		"07-unnamed-witness-only":                     {"section": "10", "says": "is IGNORED, not refused"},
		"08-forged-cosignature":                       {"section": "10", "says": "must verify"},
		"09-extension-line":                           {"section": "6", "says": "exactly three lines"},
		"10-wrong-body-origin":                        {"section": "10", "says": "which log this is about"},
		"11-forged-cosignature-with-quorum":           {"section": "10", "says": "per line, not per witness"},
		"12-second-line-from-one-witness":             {"section": "10", "says": "per line, not per witness"},
		"13-ascii-dash-signature":                     {"section": "7", "says": "signature line per signer"},
		"14-unterminated-signature-block":             {"section": "7", "says": "including the last, ends in one"},
		"15-size-leading-zero":                        {"section": "6", "says": "no leading zeroes"},
		"17-root-wrong-length":                        {"section": "6", "says": "32 bytes once decoded"},
		"21-origin-with-a-suffix":                     {"section": "10", "says": "cp.origin == norn.trust.origin"},
		"22-origin-case-changed":                      {"section": "10", "says": "cp.origin == norn.trust.origin"},
		"23-extra-final-newline":                      {"section": "7", "says": "a second `0x0A` after the final signature creates a forbidden blank line"},
		"24-log-key-other-algorithm-length":           {"section": "10", "says": "A 76-byte payload under the log's `0x01` key fails here"},
		"28-witness-key-other-algorithm-length":       {"section": "10", "says": "A 68-byte payload under a listed witness's"},
		"29-root-unpadded":                            {"section": "6", "says": "standard base64 with padding, 32 bytes once decoded"},
		"30-noncanonical-size-under-untrusted-signer": {"section": "10", "says": "norn.trust.log_key"},
		"25-signature-nonzero-pad-bits":               {"section": "7", "says": "unused pad bits MUST be zero"},
		"26-cosignature-nonzero-pad-bits":             {"section": "7", "says": "unused pad bits MUST be zero"},
		"27-root-nonzero-pad-bits":                    {"section": "6", "says": "unused pad bits MUST be zero"},
		"18-signature-name-with-space":                {"section": "7", "says": "contains no space"},
		"19-signature-unpadded-base64":                {"section": "7", "says": "standard base64 **with padding**"},
		"20-signature-payload-too-long":               {"section": "10", "says": "Any length but 68 under the log's key fails here too"},
		"16-two-log-signatures":                       {"section": "10", "says": "Every signature line whose name and key id match"},
	}
	for name := range reasons {
		if _, ok := rules[name]; !ok {
			return fmt.Errorf("checkpoint case %q names no section: every negative must "+
				"say which section states the rule that refuses it", name)
		}
	}
	// D-061, §10.1: the code each file is refused with, in the order the
	// verifier checks. Without it a reader that runs two checks in the other
	// order refuses every file here too, and the suite cannot tell: 01 is
	// `note` and not `log-signature`, 03 is `log-signature` and not `origin`.
	codes := map[string]refusal.Code{
		"31-cosignature-S-plus-L":                     refusal.Cosignature,
		"01-unsigned":                                 refusal.Note,
		"02-wrong-log-key":                            refusal.LogSignature,
		"03-wrong-origin":                             refusal.LogSignature,
		"04-forged-log-signature":                     refusal.LogSignature,
		"05-one-cosignature-short":                    refusal.Quorum,
		"06-no-cosignatures":                          refusal.Quorum,
		"07-unnamed-witness-only":                     refusal.Quorum,
		"08-forged-cosignature":                       refusal.Cosignature,
		"09-extension-line":                           refusal.Checkpoint,
		"10-wrong-body-origin":                        refusal.Origin,
		"11-forged-cosignature-with-quorum":           refusal.Cosignature,
		"12-second-line-from-one-witness":             refusal.Cosignature,
		"13-ascii-dash-signature":                     refusal.Note,
		"14-unterminated-signature-block":             refusal.Note,
		"15-size-leading-zero":                        refusal.Checkpoint,
		"16-two-log-signatures":                       refusal.LogSignature,
		"17-root-wrong-length":                        refusal.Checkpoint,
		"18-signature-name-with-space":                refusal.Note,
		"19-signature-unpadded-base64":                refusal.Note,
		"20-signature-payload-too-long":               refusal.LogSignature,
		"21-origin-with-a-suffix":                     refusal.Origin,
		"22-origin-case-changed":                      refusal.Origin,
		"23-extra-final-newline":                      refusal.Note,
		"24-log-key-other-algorithm-length":           refusal.LogSignature,
		"25-signature-nonzero-pad-bits":               refusal.Note,
		"26-cosignature-nonzero-pad-bits":             refusal.Note,
		"27-root-nonzero-pad-bits":                    refusal.Checkpoint,
		"28-witness-key-other-algorithm-length":       refusal.Cosignature,
		"29-root-unpadded":                            refusal.Checkpoint,
		"30-noncanonical-size-under-untrusted-signer": refusal.LogSignature,
	}
	if err := checkCodes("checkpoints-bad", names, codes, refusal.Known); err != nil {
		return err
	}

	manifest := map[string]any{
		"cases":                   names,
		"reasons":                 reasons,
		"rules":                   rules,
		"signature_blind_accepts": blind,
		"codes":                   codes,
		"comment": "each file is served in place of served/checkpoint, over the honest tiles, " +
			"under trust.cbor; every one MUST be refused, with the SPEC §10.1 code `codes` " +
			"names for it. `signature_blind_accepts` lists the ones whose only defect is a " +
			"signature that does not verify: a reader that never calls Ed25519 accepts " +
			"exactly those, and nothing else here",
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cases.json"), append(raw, '\n'), 0o644)
}
