package server

import (
	"net"
	"net/http"
)

// The operator's interface: commands for whoever runs this server, never
// part of the API. It is served on a Unix socket that only the server's own
// user can open (irongalld serve -admin-socket), and never on the API's
// listener, so nothing that reaches the API reaches it.

// ClearAddress forgets what the limits keyed by a caller's address hold of
// ip: its calls with no pass, its misses, its registrations and its sends
// before their pass, each bucket full again as if the address had never been
// seen. ip is an IPv4 address or any IPv6 address of a /64, which is how the
// limits key a caller (ipKey). It returns that key and the names of the
// limits that held anything of it, and false if ip is no address.
func (s *Server) ClearAddress(ip string) (key string, cleared []string, ok bool) {
	if net.ParseIP(ip) == nil {
		return "", nil, false
	}
	key, now := ipKey(ip), s.now()
	for _, l := range []struct {
		name string
		bs   *buckets
	}{
		{"public", s.public},
		{"misses", s.misses},
		{"registrations", s.regs},
		{"sends", s.sendIPs},
	} {
		if l.bs.clear(key, now) {
			cleared = append(cleared, l.name)
		}
	}
	return key, cleared, true
}

// AdminHandler is the operator's interface: POST /limits/clear?ip=<address>
// answers {"address":"<the key cleared>","cleared":[<the limits that held
// anything of it>]} (ClearAddress).
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /limits/clear", func(w http.ResponseWriter, r *http.Request) {
		key, cleared, ok := s.ClearAddress(r.URL.Query().Get("ip"))
		if !ok {
			http.Error(w, "ip: not an IPv4 or IPv6 address", http.StatusBadRequest)
			return
		}
		if cleared == nil {
			cleared = []string{}
		}
		if s.log != nil {
			s.log.Printf("the operator cleared one address's limits: %v", cleared) // never the address: this server logs none
		}
		writeJSON(w, http.StatusOK, struct {
			Address string   `json:"address"`
			Cleared []string `json:"cleared"`
		}{key, cleared})
	})
	return mux
}
