package server

import (
	"bytes"
	_ "embed"
	htmltemplate "html/template"
	"net/http"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// The one page this server has outside /v1/: the page a box's link opens
// (PROTOCOL.md § Terms). It needs no store, so it is served while the API
// still answers 503. A site's other pages are not the server's.

// pageMaxAge bounds how long a cache and clients keep the page after a
// deploy changes it.
const pageMaxAge = "public, max-age=300"

//go:embed to.html
var toHTML string

// linkPage serves the page a box's link opens, <server>/to/<address>: what
// irongall is, for whoever was handed the link. It is fixed text and the
// address, never text a box supplied, for any 64 lowercase hex characters,
// the form clients take; it reads no store, so it answers before the API is
// ready. The link is a send capability: the page keeps it out of Referer
// headers and search engines.
func linkPage() http.Handler {
	t := htmltemplate.Must(htmltemplate.New("to.html").Option("missingkey=error").Parse(toHTML))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := protocol.ParseAddress(r.PathValue("addr"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var b bytes.Buffer
		if err := t.Execute(&b, struct{ Addr string }{a.String()}); err != nil {
			http.Error(w, "the page did not render", http.StatusInternalServerError)
			return
		}
		h := w.Header()
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Robots-Tag", "noindex")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", pageMaxAge)
		h.Set("X-Content-Type-Options", "nosniff")
		w.Write(b.Bytes()) //nolint:errcheck,gosec // the client went away
	})
}
