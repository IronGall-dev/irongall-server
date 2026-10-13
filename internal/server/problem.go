package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Every error body is RFC 9457 Problem Details with the extension members
// code and hint (PROTOCOL.md §13). The hint names the fix as a client command,
// never a raw shell line a malicious server could alter; detail explains it
// for generic clients.

// titles are the problem titles, one per code.
var titles = map[protocol.Code]string{
	protocol.CodeBadRequest:         "Bad request",
	protocol.CodeBadAddress:         "Bad address",
	protocol.CodeBadEncoding:        "Bad encoding",
	protocol.CodeIdentityMismatch:   "Identity mismatch",
	protocol.CodeBadKey:             "Bad key",
	protocol.CodeNotAge:             "Not an age file",
	protocol.CodeWrongRecipientType: "Wrong recipient type",
	protocol.CodeBadRevocation:      "Bad revocation",
	protocol.CodeUnauthorized:       "Unauthorized",
	protocol.CodePassExpired:        "Pass expired",
	protocol.CodeUnknownSender:      "Unknown sender",
	protocol.CodeSenderRevoked:      "Sender revoked",
	protocol.CodeSenderNotAllowed:   "Sender not allowed",
	protocol.CodeNoSuchMailbox:      "No such mailbox",
	protocol.CodeNoSuchMessage:      "No such message",
	protocol.CodeNotRevoked:         "Not revoked",
	protocol.CodeConflict:           "Conflict",
	protocol.CodeStalePrekey:        "Stale prekey",
	protocol.CodePrekeyExpired:      "Prekey expired",
	protocol.CodeRevoked:            "Revoked",
	protocol.CodeTooLarge:           "Too large",
	protocol.CodeRateLimited:        "Rate limited",
	protocol.CodePairFull:           "Pair full",
	protocol.CodeMailboxFull:        "Mailbox full",
	protocol.CodeUnavailable:        "Unavailable",
}

// problem is an error to answer with.
type problem struct {
	code       protocol.Code
	detail     string
	hint       string
	retryAfter time.Duration // 429 and 503
	// pair_full only
	unacked *int
	oldest  time.Time
}

func (p *problem) Error() string { return string(p.code) + ": " + p.detail }

func fail(code protocol.Code, hint, format string, args ...any) *problem {
	return &problem{code: code, hint: hint, detail: fmt.Sprintf(format, args...)}
}

func writeProblem(w http.ResponseWriter, p *problem) {
	status := p.code.Status()
	body := protocol.Problem{
		Type:   p.code.TypeURI(),
		Title:  titles[p.code],
		Status: status,
		Detail: p.detail,
		Code:   p.code,
		Hint:   p.hint,
	}
	if p.unacked != nil {
		body.Unacked = p.unacked
		body.OldestExpiresAt = p.oldest.UTC().Format(protocol.TimeLayout)
	}
	h := w.Header()
	h.Set("Content-Type", protocol.ProblemContentType)
	if status == http.StatusUnauthorized {
		h.Set("WWW-Authenticate", protocol.PassScheme) // RFC 9110 §11.6.1
	}
	if p.retryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(retrySeconds(p.retryAfter)))
	}
	writeBody(w, status, body)
}

// writeJSON answers with compact JSON, no HTML escaping.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	writeBody(w, status, v)
}

func writeBody(w http.ResponseWriter, status int, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}
