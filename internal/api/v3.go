package api

import (
	"errors"
	"net/http"
	"strconv"

	"cyberboba/internal/config"
	"cyberboba/internal/intercept"
)

func (s *Server) v3Routes() {
	m := s.mux
	need := func(w http.ResponseWriter) *intercept.Engine {
		if s.d.Icpt == nil {
			writeErr(w, 503, errors.New("intercept engine is disabled"))
			return nil
		}
		return s.d.Icpt
	}

	// --- rewrites ---
	m.HandleFunc("GET /api/intercept/rewrites", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"rewrites": s.d.Store.Get().Intercept.Rewrites})
	})
	m.HandleFunc("PUT /api/intercept/rewrites", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Rewrites []config.Rewrite `json:"rewrites"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error { c.Intercept.Rewrites = in.Rewrites; return nil }); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, map[string]interface{}{"rewrites": s.d.Store.Get().Intercept.Rewrites})
	})

	// --- sessions ---
	m.HandleFunc("POST /api/intercept/session/save", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		var in struct {
			Path string `json:"path"`
		}
		_ = readJSON(r, &in)
		dir := s.d.Store.Get().Intercept.SessionDir
		path, n, err := e.SaveSession(dir, in.Path)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, map[string]interface{}{"path": path, "flows": n})
	})
	m.HandleFunc("POST /api/intercept/session/load", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		var in struct {
			Path    string `json:"path"`
			Replace bool   `json:"replace"`
		}
		if err := readJSON(r, &in); err != nil || in.Path == "" {
			writeErr(w, 400, errors.New("path is required"))
			return
		}
		n, err := e.LoadSession(in.Path, in.Replace)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, map[string]interface{}{"loaded": n, "flows": e.Store().Count()})
	})
	m.HandleFunc("GET /api/intercept/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"sessions": intercept.ListSessions(s.d.Store.Get().Intercept.SessionDir)})
	})

	// --- tags ---
	m.HandleFunc("GET /api/tags", func(w http.ResponseWriter, r *http.Request) {
		if s.d.Tags == nil {
			writeJSON(w, map[string]interface{}{"tags": []interface{}{}, "available": false})
			return
		}
		writeJSON(w, map[string]interface{}{"tags": s.d.Tags.List(), "available": s.d.Tags.Available()})
	})
	m.HandleFunc("POST /api/tags/attach", func(w http.ResponseWriter, r *http.Request) {
		if s.d.Tags == nil || !s.d.Tags.Available() {
			writeErr(w, 503, errors.New("net_cls cgroup not available (need root and cgroup v1 net_cls)"))
			return
		}
		var in struct {
			PID int    `json:"pid"`
			Tag string `json:"tag"`
		}
		if err := readJSON(r, &in); err != nil || in.PID <= 0 || in.Tag == "" {
			writeErr(w, 400, errors.New("pid and tag are required"))
			return
		}
		if err := s.d.Tags.Attach(in.PID, in.Tag); err != nil {
			writeErr(w, 500, err)
			return
		}
		_, cid, _ := s.d.Tags.ClassID(in.Tag)
		s.d.ReapplyTagUDP()
		writeJSON(w, map[string]interface{}{"ok": true, "cgroup": cid})
	})
}

// patch flow detail endpoint to honour max_body: handled in intercept.go via
// query param; here we expose a helper used there.
func maxBodyParam(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("max_body"))
	return n
}
