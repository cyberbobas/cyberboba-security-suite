package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"cyberboba/internal/config"
)

func (s *Server) dnsRoutes() {
	m := s.mux

	// Filter status + counters + config (Pi-hole-style DNS blocking).
	m.HandleFunc("GET /api/dns", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]interface{}{"config": s.d.Store.Get().DNSFilter}
		if f := s.d.DNS.Filter(); f != nil {
			out["stats"] = f.Stats()
		}
		writeJSON(w, out)
	})

	// Recent DNS queries (newest first). ?limit=200&blocked=1
	m.HandleFunc("GET /api/dns/log", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 3000 {
			limit = 200
		}
		blockedOnly := r.URL.Query().Get("blocked") == "1" || r.URL.Query().Get("blocked") == "true"
		entries := []interface{}{}
		if f := s.d.DNS.Filter(); f != nil {
			for _, e := range f.Recent(limit, blockedOnly) {
				entries = append(entries, e)
			}
		}
		writeJSON(w, map[string]interface{}{"queries": entries})
	})

	// Replace the whole DNS filter config.
	m.HandleFunc("PUT /api/dns", func(w http.ResponseWriter, r *http.Request) {
		cur := s.d.Store.Get().DNSFilter
		if err := readJSON(r, &cur); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error { c.DNSFilter = cur; return nil }); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "config": s.d.Store.Get().DNSFilter})
	})

	// Block a domain (adds to manual block list).
	m.HandleFunc("POST /api/dns/block", func(w http.ResponseWriter, r *http.Request) {
		dom, err := dnsDomainBody(r)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error {
			if !c.DNSFilter.Enabled {
				c.DNSFilter.Enabled = true // blocking a domain implies turning the filter on
			}
			for _, d := range c.DNSFilter.Block {
				if strings.EqualFold(d, dom) {
					return nil
				}
			}
			c.DNSFilter.Block = append(c.DNSFilter.Block, dom)
			// if it was explicitly allowed, drop that so the block takes effect
			c.DNSFilter.Allow = removeFold(c.DNSFilter.Allow, dom)
			return nil
		}); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "config": s.d.Store.Get().DNSFilter})
	})

	// Unblock a domain: remove from manual block and add to allow so a
	// list-blocked domain resolves again.
	m.HandleFunc("POST /api/dns/unblock", func(w http.ResponseWriter, r *http.Request) {
		dom, err := dnsDomainBody(r)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error {
			c.DNSFilter.Block = removeFold(c.DNSFilter.Block, dom)
			for _, d := range c.DNSFilter.Allow {
				if strings.EqualFold(d, dom) {
					return nil
				}
			}
			c.DNSFilter.Allow = append(c.DNSFilter.Allow, dom)
			return nil
		}); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "config": s.d.Store.Get().DNSFilter})
	})

	// Re-download the configured blocklists now.
	m.HandleFunc("POST /api/dns/refresh", func(w http.ResponseWriter, r *http.Request) {
		if f := s.d.DNS.Filter(); f != nil {
			f.Refresh()
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	// Clear the query log and counters (keeps the blocklists).
	m.HandleFunc("POST /api/dns/reset", func(w http.ResponseWriter, r *http.Request) {
		if f := s.d.DNS.Filter(); f != nil {
			f.ResetStats()
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
}

func dnsDomainBody(r *http.Request) (string, error) {
	var in struct {
		Domain string `json:"domain"`
	}
	if err := readJSON(r, &in); err != nil {
		return "", err
	}
	d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(in.Domain, ".")))
	if d == "" || !strings.Contains(d, ".") {
		return "", errors.New("a valid domain is required")
	}
	return d, nil
}

func removeFold(ss []string, v string) []string {
	out := ss[:0]
	for _, s := range ss {
		if !strings.EqualFold(s, v) {
			out = append(out, s)
		}
	}
	return out
}
