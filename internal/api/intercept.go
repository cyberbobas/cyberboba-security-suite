package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"cyberboba/internal/caido"
	"cyberboba/internal/config"
	"cyberboba/internal/intercept"
)

func (s *Server) interceptRoutes() {
	m := s.mux
	need := func(w http.ResponseWriter) *intercept.Engine {
		if s.d.Icpt == nil {
			writeErr(w, 503, errors.New("intercept engine is disabled"))
			return nil
		}
		return s.d.Icpt
	}
	view := func() map[string]interface{} {
		out := map[string]interface{}{"enabled": false}
		if s.d.Icpt != nil {
			out = toMap(s.d.Icpt.Status())
		}
		out["config"] = s.d.Store.Get().Intercept
		return out
	}

	m.HandleFunc("GET /api/intercept", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, view()) })
	m.HandleFunc("PUT /api/intercept", func(w http.ResponseWriter, r *http.Request) {
		cur := s.d.Store.Get().Intercept
		if err := readJSON(r, &cur); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error { c.Intercept = cur; return nil }); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, view())
	})
	// --- per-app recording -------------------------------------------------
	// Recording only captures traffic that is routed through the interceptor.
	// These endpoints wire that up per application: adding an app installs a
	// managed rule (apps:[app], action:intercept) so just that program's HTTP/
	// HTTPS is transparently MITM'd and recorded, and flips recording on. This
	// is the "record only Chromium / only Claude" control.
	const recMark = "cyberboba:record"
	recApps := func(c *config.Config) []string {
		var apps []string
		for _, r := range c.Rules {
			if r.Comment == recMark {
				apps = append(apps, r.Apps...)
			}
		}
		if apps == nil {
			apps = []string{}
		}
		return apps
	}
	m.HandleFunc("GET /api/intercept/record", func(w http.ResponseWriter, r *http.Request) {
		c := s.d.Store.Get()
		rec := s.d.Icpt != nil && s.d.Icpt.Status().Recording
		writeJSON(w, map[string]interface{}{"apps": recApps(c), "recording": rec, "enabled": s.d.Icpt != nil})
	})
	m.HandleFunc("POST /api/intercept/record", func(w http.ResponseWriter, r *http.Request) {
		if need(w) == nil {
			return
		}
		var in struct {
			App string `json:"app"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		app := strings.TrimSpace(in.App)
		if app == "" {
			writeErr(w, 400, errors.New("app is required"))
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error {
			for _, rl := range c.Rules { // already recording this app?
				if rl.Comment == recMark {
					for _, a := range rl.Apps {
						if strings.EqualFold(a, app) {
							return nil
						}
					}
				}
			}
			t := true
			rule := config.Rule{Name: "Record: " + app, Enabled: &t, Comment: recMark,
				Apps: []string{app}, Action: config.ActionIntercept}
			// Insert before the first catch-all rule (no apps/targets/users/ports)
			// so the record rule actually matches before a trailing "Default".
			idx := len(c.Rules)
			for i, rl := range c.Rules {
				if len(rl.Apps) == 0 && len(rl.Targets) == 0 && len(rl.Users) == 0 && len(rl.Ports) == 0 && len(rl.Protocols) == 0 {
					idx = i
					break
				}
			}
			c.Rules = append(c.Rules[:idx:idx], append([]config.Rule{rule}, c.Rules[idx:]...)...)
			return nil
		}); err != nil {
			writeErr(w, 400, err)
			return
		}
		rec := true
		s.d.Icpt.Toggle(&rec, nil, nil, nil) // recording must be on to capture
		c := s.d.Store.Get()
		writeJSON(w, map[string]interface{}{"ok": true, "apps": recApps(c), "recording": true})
	})
	m.HandleFunc("DELETE /api/intercept/record", func(w http.ResponseWriter, r *http.Request) {
		app := strings.TrimSpace(r.URL.Query().Get("app"))
		if app == "" {
			var in struct {
				App string `json:"app"`
			}
			_ = readJSON(r, &in)
			app = strings.TrimSpace(in.App)
		}
		if app == "" {
			writeErr(w, 400, errors.New("app is required"))
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error {
			out := c.Rules[:0]
			for _, rl := range c.Rules {
				if rl.Comment == recMark && len(rl.Apps) == 1 && strings.EqualFold(rl.Apps[0], app) {
					continue // drop this managed record rule
				}
				out = append(out, rl)
			}
			c.Rules = out
			return nil
		}); err != nil {
			writeErr(w, 400, err)
			return
		}
		c := s.d.Store.Get()
		writeJSON(w, map[string]interface{}{"ok": true, "apps": recApps(c)})
	})

	m.HandleFunc("POST /api/intercept/toggle", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		var in struct {
			Recording     *bool `json:"recording"`
			Scan          *bool `json:"scan"`
			HoldRequests  *bool `json:"hold_requests"`
			HoldResponses *bool `json:"hold_responses"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		e.Toggle(in.Recording, in.Scan, in.HoldRequests, in.HoldResponses)
		writeJSON(w, view())
	})

	m.HandleFunc("GET /api/intercept/flows", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit == 0 {
			limit = 500
		}
		offset, _ := strconv.Atoi(q.Get("offset"))
		f := intercept.Filter{Q: q.Get("q"), Host: q.Get("host"), Method: q.Get("method"), Status: q.Get("status"),
			ScopeOnly: q.Get("scope") == "1" || q.Get("scope") == "true", Source: q.Get("source"), Body: q.Get("body")}
		if ids := q.Get("ids"); ids != "" {
			f.IDs = map[uint64]bool{}
			for _, p := range strings.Split(ids, ",") {
				if n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 64); err == nil {
					f.IDs[n] = true
				}
			}
		}
		flows, total := e.Store().List(f, limit, offset)
		writeJSON(w, map[string]interface{}{"flows": flows, "total": total})
	})
	// Passive security scan findings aggregated across all recorded flows,
	// grouped by rule, newest-affected first, with severity totals.
	m.HandleFunc("GET /api/intercept/findings", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		flows, _ := e.Store().List(intercept.Filter{}, 0, 0)
		type grp struct {
			Rule     string   `json:"rule"`
			Title    string   `json:"title"`
			Severity string   `json:"severity"`
			Count    int      `json:"count"`
			Flows    []uint64 `json:"flows"`
			Sample   string   `json:"sample"`
		}
		order := []string{}
		byRule := map[string]*grp{}
		sevTotals := map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
		for i := range flows {
			f := &flows[i]
			for _, fd := range f.Findings {
				g := byRule[fd.Rule]
				if g == nil {
					g = &grp{Rule: fd.Rule, Title: fd.Title, Severity: fd.Severity, Sample: fd.Detail}
					byRule[fd.Rule] = g
					order = append(order, fd.Rule)
				}
				g.Count++
				if len(g.Flows) < 200 {
					g.Flows = append(g.Flows, f.ID)
				}
				sevTotals[fd.Severity]++
			}
		}
		rank := map[string]int{"high": 0, "medium": 1, "low": 2, "info": 3}
		groups := make([]*grp, 0, len(order))
		for _, rule := range order {
			groups = append(groups, byRule[rule])
		}
		sort.Slice(groups, func(i, j int) bool {
			if rank[groups[i].Severity] != rank[groups[j].Severity] {
				return rank[groups[i].Severity] < rank[groups[j].Severity]
			}
			return groups[i].Count > groups[j].Count
		})
		writeJSON(w, map[string]interface{}{"groups": groups, "severity": sevTotals, "scanned_flows": len(flows)})
	})
	m.HandleFunc("DELETE /api/intercept/flows", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		e.Store().Clear()
		writeJSON(w, map[string]bool{"ok": true})
	})
	m.HandleFunc("GET /api/intercept/flows/{id}", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
		f := e.Store().Get(id)
		if f == nil {
			writeErr(w, 404, fmt.Errorf("flow %d not found", id))
			return
		}
		if mb := maxBodyParam(r); mb > 0 {
			writeJSON(w, f.DetailCut(mb))
			return
		}
		writeJSON(w, f.Detail())
	})
	m.HandleFunc("DELETE /api/intercept/flows/{id}", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
		writeJSON(w, map[string]bool{"ok": e.Store().Delete(id)})
	})
	m.HandleFunc("GET /api/intercept/flows/{id}/export", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
		f := e.Store().Get(id)
		if f == nil {
			writeErr(w, 404, fmt.Errorf("flow %d not found", id))
			return
		}
		switch r.URL.Query().Get("format") {
		case "curl":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte(intercept.Curl(f)))
		case "raw":
			d := f.Detail()
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=flow-%d.txt", id))
			w.Write([]byte(d.ReqRaw + "\r\n\r\n" + d.RespRaw))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=flow-%d.har", id))
			w.Write(intercept.HAR([]*intercept.Flow{f}))
		}
	})
	m.HandleFunc("GET /api/intercept/export", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		all := e.Store().All()
		q := r.URL.Query()
		if q.Get("q") != "" || q.Get("host") != "" || q.Get("scope") == "1" {
			f := intercept.Filter{Q: q.Get("q"), Host: q.Get("host"), ScopeOnly: q.Get("scope") == "1"}
			sel, _ := e.Store().List(f, 0, 0)
			keep := map[uint64]bool{}
			for _, x := range sel {
				keep[x.ID] = true
			}
			var filtered []*intercept.Flow
			for _, x := range all {
				if keep[x.ID] {
					filtered = append(filtered, x)
				}
			}
			all = filtered
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=cyberboba-"+time.Now().Format("20060102-150405")+".har")
		w.Write(intercept.HAR(all))
	})

	m.HandleFunc("GET /api/intercept/pending", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		writeJSON(w, map[string]interface{}{"pending": e.Pending()})
	})
	m.HandleFunc("POST /api/intercept/pending/forward-all", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		writeJSON(w, map[string]int{"forwarded": e.ForwardAll()})
	})
	m.HandleFunc("POST /api/intercept/pending/{id}/forward", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
		var in struct {
			Raw string `json:"raw"`
		}
		_ = readJSON(r, &in)
		if err := e.Forward(id, in.Raw); err != nil {
			writeErr(w, 404, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	m.HandleFunc("POST /api/intercept/pending/{id}/drop", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
		if err := e.Drop(id); err != nil {
			writeErr(w, 404, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	m.HandleFunc("POST /api/intercept/send", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		var in struct {
			Host            string `json:"host"`
			Port            int    `json:"port"`
			TLS             bool   `json:"tls"`
			Raw             string `json:"raw"`
			FollowRedirects bool   `json:"follow_redirects"`
			TimeoutSec      int    `json:"timeout_sec"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if strings.TrimSpace(in.Raw) == "" {
			writeErr(w, 400, errors.New("raw request is required"))
			return
		}
		d, err := e.Send(in.Host, in.Port, in.TLS, in.Raw, in.FollowRedirects, time.Duration(in.TimeoutSec)*time.Second)
		out := map[string]interface{}{"flow": d}
		if err != nil {
			out["error"] = err.Error()
		}
		writeJSON(w, out)
	})

	m.HandleFunc("GET /api/intercept/ca", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=cyberboba-ca.crt")
		w.Write(e.CA().PEM())
	})
	m.HandleFunc("POST /api/intercept/ca/install", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		inst, errs := caido.InstallCA(e.CA().CertPath())
		if errs == nil {
			errs = []string{}
		}
		writeJSON(w, map[string]interface{}{"ok": len(inst) > 0, "installed_into": inst, "errors": errs})
	})
	m.HandleFunc("POST /api/intercept/ca/regenerate", func(w http.ResponseWriter, r *http.Request) {
		e := need(w)
		if e == nil {
			return
		}
		if err := e.CA().Regenerate(); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, view())
	})

	m.HandleFunc("GET /api/config/export", func(w http.ResponseWriter, r *http.Request) {
		b, _ := s.d.Store.Get().Marshal()
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Header().Set("Content-Disposition", "attachment; filename=cyberboba-config.yaml")
		w.Write(b)
	})
}
