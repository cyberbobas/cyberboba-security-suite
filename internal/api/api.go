// Package api serves the JSON control API and the embedded web UI.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cyberboba/internal/app"
	"cyberboba/internal/caido"
	"cyberboba/internal/config"
	"cyberboba/internal/mcp"
	"cyberboba/internal/rules"
	"cyberboba/internal/stats"
	"cyberboba/internal/upstream"
	"cyberboba/internal/vpn"
)

// Server is the HTTP API.
type Server struct {
	d     *app.Daemon
	mux   *http.ServeMux
	webFS fs.FS
	srvs  []*http.Server
	mcp   *mcp.Server
}

// New builds the server. webFS may be nil (API only).
func New(d *app.Daemon, webFS fs.FS) *Server {
	s := &Server{d: d, mux: http.NewServeMux(), webFS: webFS}
	s.routes()
	return s
}

// Handler returns the root handler (useful for tests).
func (s *Server) Handler() http.Handler { return s.mux }

// ListenAndServe starts the unix socket and optional TCP listener.
func (s *Server) ListenAndServe(unixPath, tcpAddr, token string) error {
	if unixPath != "" {
		_ = os.MkdirAll(filepath.Dir(unixPath), 0o755)
		_ = os.Remove(unixPath)
		ln, err := net.Listen("unix", unixPath)
		if err != nil {
			return fmt.Errorf("unix socket: %w", err)
		}
		_ = os.Chmod(unixPath, 0o666)
		srv := &http.Server{Handler: s.mux}
		s.srvs = append(s.srvs, srv)
		go srv.Serve(ln)
	}
	if tcpAddr != "" {
		ln, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			return fmt.Errorf("api listener: %w", err)
		}
		var h http.Handler = s.mux
		if token != "" {
			h = s.auth(token, s.mux)
		}
		srv := &http.Server{Handler: h}
		s.srvs = append(s.srvs, srv)
		go srv.Serve(ln)
	}
	return nil
}

// Shutdown stops the listeners.
func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, srv := range s.srvs {
		_ = srv.Shutdown(ctx)
	}
}

func (s *Server) auth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/mcp" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if got == "" {
				got = r.URL.Query().Get("token")
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				writeErr(w, 401, errors.New("unauthorized"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v interface{}) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil
	}
	return json.Unmarshal(body, v)
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/status", s.status)
	m.HandleFunc("POST /api/proxify/enable", func(w http.ResponseWriter, r *http.Request) {
		if err := s.d.EnableNetfilterAndTags(); err != nil {
			writeErr(w, 500, err)
			return
		}
		s.status(w, r)
	})
	m.HandleFunc("POST /api/proxify/disable", func(w http.ResponseWriter, r *http.Request) {
		if err := s.d.DisableNetfilter(); err != nil {
			writeErr(w, 500, err)
			return
		}
		s.status(w, r)
	})

	m.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.d.Store.Get()) })
	m.HandleFunc("PUT /api/config", func(w http.ResponseWriter, r *http.Request) {
		cfg := config.Default()
		cfg.Rules = nil
		if err := readJSON(r, cfg); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Update(cfg); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, cfg)
	})
	m.HandleFunc("GET /api/config/yaml", func(w http.ResponseWriter, r *http.Request) {
		b, _ := s.d.Store.Get().Marshal()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(b)
	})
	m.HandleFunc("PUT /api/config/yaml", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		cfg, err := config.Parse(body)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Update(cfg); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	// rules
	m.HandleFunc("GET /api/rules", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"rules": s.d.Store.Get().Rules})
	})
	m.HandleFunc("PUT /api/rules", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Rules []config.Rule `json:"rules"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error { c.Rules = in.Rules; return nil }); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, map[string]interface{}{"rules": s.d.Store.Get().Rules})
	})
	m.HandleFunc("POST /api/rules/test", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			App, Exe, Cmd, Tag, User, Host, IP, Protocol string
			Port                                         int
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		// Convenience: when testing by app name without an explicit command
		// line, assume the name appears in the command line so cmd:<substr>
		// rules (e.g. from "Choose app") can be checked from the name alone.
		// Path rules need an explicit exe.
		cmd := in.Cmd
		if cmd == "" && in.App != "" {
			cmd = in.App
		}
		c := rules.Conn{App: in.App, Exe: in.Exe, Cmd: cmd, Tag: in.Tag, User: in.User, Host: strings.ToLower(in.Host), Port: in.Port, Proto: in.Protocol, UID: -1}
		if in.IP != "" {
			c.IP = rules.ResolveIP(in.IP)
		} else if in.Host != "" {
			if ips, err := net.LookupIP(in.Host); err == nil && len(ips) > 0 {
				c.IP, _ = netip.AddrFromSlice(ips[0])
				c.IP = c.IP.Unmap()
			}
		}
		if c.Proto == "" {
			c.Proto = "tcp"
		}
		d := s.d.Proxy.Evaluate(c)
		out := map[string]interface{}{"matched": d.Matched, "action": d.Action, "proxy": d.Proxy, "vpn": d.VPN, "ip": c.IP.String()}
		if d.Matched {
			out["rule"] = d.Rule.Name
			out["index"] = d.Index
		}
		writeJSON(w, out)
	})

	// proxies
	m.HandleFunc("GET /api/proxies", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"proxies": s.d.Store.Get().Proxies})
	})
	m.HandleFunc("PUT /api/proxies", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Proxies []config.Proxy `json:"proxies"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error { c.Proxies = in.Proxies; return nil }); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, map[string]interface{}{"proxies": s.d.Store.Get().Proxies})
	})
	m.HandleFunc("POST /api/proxies/{name}/check", s.checkProxy)

	// vpn
	m.HandleFunc("GET /api/vpn", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"vpns": s.vpnList()})
	})
	m.HandleFunc("PUT /api/vpn", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			VPNs []config.VPN `json:"vpns"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error { c.VPNs = in.VPNs; return nil }); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, map[string]interface{}{"vpns": s.vpnList()})
	})
	m.HandleFunc("POST /api/vpn/import", s.vpnImport)
	m.HandleFunc("POST /api/vpn/{name}/up", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := s.d.VPN.Up(name); err != nil {
			writeErr(w, 500, err)
			return
		}
		st, _ := s.d.VPN.Status(name)
		writeJSON(w, st)
	})
	m.HandleFunc("POST /api/vpn/{name}/down", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := s.d.VPN.Down(name); err != nil {
			writeErr(w, 500, err)
			return
		}
		st, _ := s.d.VPN.Status(name)
		writeJSON(w, st)
	})
	m.HandleFunc("GET /api/vpn/{name}/log", func(w http.ResponseWriter, r *http.Request) {
		lines, err := s.d.VPN.Log(r.PathValue("name"))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		writeJSON(w, map[string]interface{}{"lines": lines})
	})

	// caido
	m.HandleFunc("GET /api/caido", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.caidoView()) })
	m.HandleFunc("PUT /api/caido", func(w http.ResponseWriter, r *http.Request) {
		cur := s.d.Store.Get().Caido
		if err := readJSON(r, &cur); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error { c.Caido = cur; return nil }); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, s.caidoView())
	})
	m.HandleFunc("POST /api/caido/start", func(w http.ResponseWriter, r *http.Request) {
		if err := s.d.Caido.Start(); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, s.caidoView())
	})
	m.HandleFunc("POST /api/caido/stop", func(w http.ResponseWriter, r *http.Request) {
		_ = s.d.Caido.Stop()
		writeJSON(w, s.caidoView())
	})
	m.HandleFunc("POST /api/caido/restart", func(w http.ResponseWriter, r *http.Request) {
		if err := s.d.Caido.Restart(); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, s.caidoView())
	})
	m.HandleFunc("POST /api/caido/install", func(w http.ResponseWriter, r *http.Request) {
		bin, ver, err := s.d.Caido.Install("")
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		_ = s.d.Store.Mutate(func(c *config.Config) error {
			if c.Caido.Binary == "" {
				c.Caido.Binary = bin
			}
			return nil
		})
		writeJSON(w, map[string]interface{}{"ok": true, "binary": bin, "version": ver})
	})
	m.HandleFunc("GET /api/caido/log", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"lines": s.d.Caido.Log()})
	})
	m.HandleFunc("POST /api/caido/ca/install", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Path string `json:"path"`
		}
		_ = readJSON(r, &in)
		if in.Path == "" {
			in.Path = s.d.Store.Get().Caido.CACert
		}
		if in.Path == "" {
			writeErr(w, 400, errors.New("no certificate path; export ca.crt from the Caido UI and set caido.ca_cert"))
			return
		}
		inst, errs := caido.InstallCA(in.Path)
		if errs == nil {
			errs = []string{}
		}
		_ = s.d.Store.Mutate(func(c *config.Config) error { c.Caido.CACert = in.Path; return nil })
		writeJSON(w, map[string]interface{}{"ok": len(inst) > 0, "installed_into": inst, "errors": errs})
	})

	// connections
	m.HandleFunc("GET /api/connections", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit == 0 {
			limit = 500
		}
		closed := r.URL.Query().Get("closed") != "0" && r.URL.Query().Get("closed") != "false"
		writeJSON(w, map[string]interface{}{"connections": s.d.Tracker.List(limit, closed)})
	})
	m.HandleFunc("DELETE /api/connections", func(w http.ResponseWriter, r *http.Request) {
		s.d.Tracker.ClearClosed()
		writeJSON(w, map[string]bool{"ok": true})
	})
	m.HandleFunc("POST /api/connections/{id}/close", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
		writeJSON(w, map[string]bool{"ok": s.d.Tracker.Kill(id)})
	})

	m.HandleFunc("GET /api/events", s.events)
	m.HandleFunc("GET /api/log", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		writeJSON(w, map[string]interface{}{"lines": s.d.Tracker.Logs(n)})
	})
	m.HandleFunc("GET /api/processes", func(w http.ResponseWriter, r *http.Request) {
		ps := s.d.Procs.Snapshot()
		out := make([]map[string]interface{}, 0, len(ps))
		for _, p := range ps {
			out = append(out, map[string]interface{}{"pid": p.PID, "name": p.Name, "exe": p.Exe, "user": p.User})
		}
		writeJSON(w, map[string]interface{}{"processes": out})
	})
	m.HandleFunc("GET /api/doctor", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"checks": s.d.Doctor()})
	})
	m.HandleFunc("GET /api/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAPISpec)
	})

	s.interceptRoutes()
	s.topoRoutes()
	s.procmonRoutes()
	s.bandwidthRoutes()
	s.dnsRoutes()
	s.aiRoutes()
	s.autostartRoutes()
	s.v3Routes()
	m.HandleFunc("POST /mcp", s.handleMCP)
	m.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "POST")
		writeErr(w, 405, errors.New("use POST for MCP Streamable HTTP"))
	})
	if s.webFS != nil {
		// The web UI is served from the localhost control plane and changes on
		// every daemon upgrade. Tell the browser never to reuse a cached asset
		// without revalidating, so a rebuilt UI always shows up on reload.
		fileSrv := http.FileServer(http.FS(s.webFS))
		m.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
			fileSrv.ServeHTTP(w, r)
		}))
	}
}

// toMap converts a struct to a generic map through JSON.
func toMap(v interface{}) map[string]interface{} {
	b, _ := json.Marshal(v)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	if m == nil {
		m = map[string]interface{}{}
	}
	return m
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	cfg := s.d.Store.Get()
	writeJSON(w, map[string]interface{}{
		"version":    app.Version,
		"uptime_sec": int(time.Since(s.d.Started).Seconds()),
		"proxify": map[string]interface{}{"enabled": s.d.NetfilterActive(), "listen_tcp": cfg.Proxifier.ListenTCP,
			"listen_dns": cfg.Proxifier.ListenDNS, "listen_socks": cfg.Proxifier.ListenSOCKS, "listen_http": cfg.Proxifier.ListenHTTP, "ipv6": cfg.Proxifier.IPv6, "block_quic": cfg.Proxifier.BlockQUIC,
			"netfilter_installed": s.d.NetfilterActive()},
		"stats":     s.d.Tracker.Summary(),
		"vpns":      s.d.VPN.All(),
		"caido":     s.d.Caido.Status(),
		"intercept": s.interceptSummary(),
		"warnings":  s.d.Warnings(),
	})
}

func (s *Server) interceptSummary() map[string]interface{} {
	if s.d.Icpt == nil {
		return map[string]interface{}{"enabled": false}
	}
	st := s.d.Icpt.Status()
	return map[string]interface{}{"enabled": st.Enabled, "listen": st.Listen, "recording": st.Recording,
		"hold_requests": st.HoldRequests, "hold_responses": st.HoldResponses, "flows": st.Flows, "pending": st.Pending}
}

type vpnView struct {
	vpn.Status
	Config config.VPN `json:"config"`
}

func (s *Server) vpnList() []vpnView {
	cfg := s.d.Store.Get()
	sts := s.d.VPN.All()
	out := make([]vpnView, 0, len(sts))
	for _, st := range sts {
		v := vpnView{Status: st}
		if p := cfg.VPNByName(st.Name); p != nil {
			v.Config = *p
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) vpnImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string         `json:"name"`
		Type    config.VPNType `json:"type"`
		Content string         `json:"content"`
		Mode    config.VPNMode `json:"mode"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, 400, err)
		return
	}
	if in.Name == "" || in.Content == "" {
		writeErr(w, 400, errors.New("name and content are required"))
		return
	}
	if in.Type == "" {
		if strings.Contains(in.Content, "[Interface]") {
			in.Type = config.VPNWireGuard
		} else {
			in.Type = config.VPNOpenVPN
		}
	}
	if in.Mode == "" {
		in.Mode = vpn.InferMode(in.Content)
	}
	path, err := s.d.VPN.Import(s.d.VPNDir, in.Name, in.Type, in.Content)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	err = s.d.Store.Mutate(func(c *config.Config) error {
		for i := range c.VPNs {
			if c.VPNs[i].Name == in.Name {
				c.VPNs[i].Config, c.VPNs[i].Type, c.VPNs[i].Mode = path, in.Type, in.Mode
				return nil
			}
		}
		c.VPNs = append(c.VPNs, config.VPN{Name: in.Name, Type: in.Type, Config: path, Mode: in.Mode})
		return nil
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, map[string]interface{}{"vpns": s.vpnList()})
}

func (s *Server) caidoView() map[string]interface{} {
	st := s.d.Caido.Status()
	b, _ := json.Marshal(st)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	m["config"] = s.d.Store.Get().Caido
	return m
}

func (s *Server) checkProxy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		URL string `json:"url"`
	}
	_ = readJSON(r, &in)
	if in.URL == "" {
		in.URL = "https://api.ipify.org/?format=text"
	}
	if s.d.Dialer.Proxy(name) == nil {
		writeErr(w, 404, fmt.Errorf("unknown proxy %q", name))
		return
	}
	start := time.Now()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var p int
			fmt.Sscanf(port, "%d", &p)
			t := upstream.Target{Host: host, Port: p}
			if a, err := netip.ParseAddr(host); err == nil {
				t.IP = a
			} else if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host); err == nil && len(ips) > 0 {
				t.IP = ips[0].Unmap()
			} else {
				return nil, fmt.Errorf("resolve %s: %v", host, err)
			}
			c, _, err := s.d.Dialer.Dial(ctx, upstream.Route{Action: config.ActionProxy, Proxy: name}, t)
			return c, err
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	cl := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	resp, err := cl.Get(in.URL)
	out := map[string]interface{}{"ok": false, "latency_ms": time.Since(start).Milliseconds(), "error": ""}
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, out)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	out["ok"] = resp.StatusCode < 400
	out["status"] = resp.StatusCode
	if ip := strings.TrimSpace(string(body)); len(ip) < 64 && net.ParseIP(ip) != nil {
		out["exit_ip"] = ip
	}
	writeJSON(w, out)
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	ch, cancel := s.d.Tracker.Subscribe()
	defer cancel()
	fmt.Fprintf(w, "event: stats\ndata: %s\n\n", stats.MarshalEvent(stats.Event{Data: s.d.Tracker.Summary()}))
	fl.Flush()
	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keep.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		case e := <-ch:
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, stats.MarshalEvent(e))
			fl.Flush()
		}
	}
}
