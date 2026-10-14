package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"cyberboba/internal/config"
)

func (s *Server) firewallRoutes() {
	m := s.mux

	m.HandleFunc("GET /api/firewall", func(w http.ResponseWriter, r *http.Request) {
		cfg := s.d.Store.Get()
		out := s.d.FW.Status()
		out["config"] = cfg.Firewall
		writeJSON(w, out)
	})

	m.HandleFunc("PUT /api/firewall", func(w http.ResponseWriter, r *http.Request) {
		var in config.Firewall
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error { c.Firewall = in; return nil }); err != nil {
			writeErr(w, 400, err)
			return
		}
		out := s.d.FW.Status()
		out["config"] = s.d.Store.Get().Firewall
		writeJSON(w, out)
	})

	m.HandleFunc("GET /api/firewall/pending", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"pending": s.d.FW.Pending()})
	})

	// Recent firewall decisions (newest first): what was blocked, prompted or
	// auto-learned — the "what did the firewall do / what did it block" view.
	m.HandleFunc("GET /api/firewall/activity", func(w http.ResponseWriter, r *http.Request) {
		limit := 200
		if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
			limit = n
		}
		blockedOnly := r.URL.Query().Get("blocked") == "1" || r.URL.Query().Get("blocked") == "true"
		writeJSON(w, map[string]interface{}{"activity": s.d.FW.ActivityLog(limit, blockedOnly)})
	})

	m.HandleFunc("POST /api/firewall/answer", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ID       uint64 `json:"id"`
			Allow    bool   `json:"allow"`
			Remember bool   `json:"remember"`
		}
		if err := readJSON(r, &in); err != nil || in.ID == 0 {
			writeErr(w, 400, errors.New("id is required"))
			return
		}
		if !s.d.FW.Answer(in.ID, in.Allow, in.Remember) {
			writeErr(w, 404, errors.New("no such pending ask (it may have timed out)"))
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true})
	})

	m.HandleFunc("POST /api/firewall/answer_all", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Allow bool `json:"allow"`
		}
		_ = readJSON(r, &in)
		n := s.d.FW.AnswerAll(in.Allow)
		writeJSON(w, map[string]interface{}{"answered": n, "allow": in.Allow})
	})

	// convenience toggles (persisted)
	toggle := func(field string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var in struct {
				On bool `json:"on"`
			}
			_ = readJSON(r, &in)
			if err := s.d.Store.Mutate(func(c *config.Config) error {
				switch field {
				case "lock":
					c.Firewall.InternetLock = in.On
				case "stealth":
					c.Firewall.Stealth = in.On
				case "enabled":
					c.Firewall.Enabled = in.On
				}
				return nil
			}); err != nil {
				writeErr(w, 400, err)
				return
			}
			out := s.d.FW.Status()
			out["config"] = s.d.Store.Get().Firewall
			writeJSON(w, out)
		}
	}
	m.HandleFunc("POST /api/firewall/lock", toggle("lock"))
	m.HandleFunc("POST /api/firewall/stealth", toggle("stealth"))
	m.HandleFunc("POST /api/firewall/enable", toggle("enabled"))

	// host blocklist: one-click block/unblock of a destination an app reached
	// (from the live map). Works even when program control is off.
	m.HandleFunc("GET /api/firewall/blocked", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"blocked_hosts": s.d.Store.Get().Firewall.BlockedHosts})
	})
	hostMut := func(add bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var in struct {
				Host string `json:"host"`
			}
			if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Host) == "" {
				writeErr(w, 400, errors.New("host is required"))
				return
			}
			host := strings.ToLower(strings.TrimSpace(in.Host))
			if err := s.d.Store.Mutate(func(c *config.Config) error {
				out := c.Firewall.BlockedHosts[:0:0]
				seen := false
				for _, h := range c.Firewall.BlockedHosts {
					if strings.ToLower(strings.TrimSpace(h)) == host {
						seen = true
						if !add {
							continue // drop it (unblock)
						}
					}
					out = append(out, h)
				}
				if add && !seen {
					out = append(out, host)
				}
				c.Firewall.BlockedHosts = out
				return nil
			}); err != nil {
				writeErr(w, 400, err)
				return
			}
			writeJSON(w, map[string]interface{}{"ok": true, "blocked_hosts": s.d.Store.Get().Firewall.BlockedHosts})
		}
	}
	m.HandleFunc("POST /api/firewall/block", hostMut(true))
	m.HandleFunc("POST /api/firewall/unblock", hostMut(false))

	m.HandleFunc("POST /api/firewall/mode", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Mode string `json:"mode"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error {
			c.Firewall.Mode = in.Mode
			c.Firewall.Enabled = in.Mode != "off"
			return nil
		}); err != nil {
			writeErr(w, 400, err)
			return
		}
		out := s.d.FW.Status()
		out["config"] = s.d.Store.Get().Firewall
		writeJSON(w, out)
	})
}
