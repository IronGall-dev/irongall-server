package server

import (
	"errors"
	"net/http"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// conditions evaluates a request's If-Match and If-None-Match for its target,
// as RFC 9110 §13.1.1 and §13.1.2 have an origin server evaluate each it
// receives, in §13.2.2's order (IronGall-dev/irongall-server#86). Every route
// calls it once it knows its target's state, after the route, the method,
// the pass, the box's calls and the read of the target, and before it acts:
// so whatever the route answers before that point, a refusal of the pass, a
// box that does not exist, a body it reads first that is refused, is
// answered as without them (§13.2.1). PROTOCOL-SERVER.md §13 has the rule.
//
// exists is whether the target has a current representation, and tag its
// entity-tag, "" where it carries none. If-Match is false for a target that
// does not exist, and otherwise read as protocol.IfMatch reads it: "*" true,
// a list true when one of its tags is tag, compared strongly, and so false
// for a target with no tag. If-None-Match is false only for a target that
// exists, where it names tag or is "*", as protocol.IfNoneMatch reads it. The
// conditions on dates (If-Unmodified-Since, If-Modified-Since) are not
// evaluated: no answer here carries a Last-Modified (§13.1.3, §13.1.4). An
// If-Range is read beside a fetch's Range alone, by protocol.RangeAsked, and
// is false there, since a fetch carries no validator (§13.1.5).
//
// It returns nil to go on; a false If-Match, or a false If-None-Match on any
// method but GET or HEAD, as 412 precondition_failed with hint; and a false
// If-None-Match on a GET or HEAD as notModified, which handle answers 304
// with tag as its ETag, and also's fields, name and value pairs: those of the
// 200 that RFC 9110 §15.4.5 has a 304 carry too.
func conditions(r *http.Request, exists bool, tag, hint string, also ...string) error {
	if lines := r.Header.Values("If-Match"); len(lines) > 0 && (!exists || !protocol.IfMatch(lines, tag)) {
		return fail(protocol.CodePreconditionFailed, hint, "the request's If-Match is false for what this server holds")
	}
	if !exists || !protocol.IfNoneMatch(r.Header.Values("If-None-Match"), tag) {
		return nil
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return fail(protocol.CodePreconditionFailed, hint, "the request's If-None-Match is false for what this server holds")
	}
	return &notModified{etag: tag, also: also}
}

// hintConditions is a 412's hint where no irongall client sends a condition.
const hintConditions = "read what the server holds again, then send it with conditions that hold, or with none: irongall sends none here"

// notModified is the answer to a GET whose If-None-Match is false: 304, with
// no content.
type notModified struct {
	etag string
	also []string
}

func (n *notModified) Error() string { return "not modified" }

// writeConditions answers what conditions returned, for a handler that
// writes its own answers: the 304, or the 412.
func writeConditions(w http.ResponseWriter, err error) {
	if n, ok := errors.AsType[*notModified](err); ok {
		n.write(w)
		return
	}
	if p, ok := errors.AsType[*problem](err); ok {
		writeProblem(w, p)
	}
}

// write answers 304 with n's fields.
func (n *notModified) write(w http.ResponseWriter) {
	h := w.Header()
	if n.etag != "" {
		h.Set("ETag", n.etag)
	}
	for i := 0; i+1 < len(n.also); i += 2 {
		h.Set(n.also[i], n.also[i+1])
	}
	w.WriteHeader(http.StatusNotModified)
}
