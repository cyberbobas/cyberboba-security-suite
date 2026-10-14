package api

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"cyberboba/internal/config"
	"cyberboba/internal/rules"
	"cyberboba/internal/upstream"
)

// dialThroughRoute fetches url through the given route and records the exit IP,
// its geolocation and the round-trip latency into out.
func (s *Server) dialThroughRoute(route upstream.Route, url string, out map[string]interface{}) {
	start := time.Now()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var port int
			fmt.Sscanf(p, "%d", &port)
			t := upstream.Target{Host: h, Port: port}
			if a, err := netip.ParseAddr(h); err == nil {
				t.IP = a
			} else if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", h); err == nil && len(ips) > 0 {
				t.IP = ips[0].Unmap()
			} else {
				return nil, fmt.Errorf("resolve %s: %v", h, err)
			}
			conn, _, err := s.d.Dialer.Dial(ctx, route, t)
			return conn, err
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	cl := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	resp, err := cl.Get(url)
	out["latency_ms"] = time.Since(start).Milliseconds()
	if err != nil {
		out["ok"] = false
		out["error"] = err.Error()
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	out["ok"] = resp.StatusCode < 400
	out["status"] = resp.StatusCode
	if ip := strings.TrimSpace(string(body)); len(ip) < 64 && net.ParseIP(ip) != nil {
		out["exit_ip"] = ip
		if info, err := s.d.Geo.LookupNow(ip); err == nil && info.Country != "" {
			out["country"] = info.Country
			out["cc"] = info.CC
			out["city"] = info.City
			out["flag"] = info.Flag
			out["isp"] = info.ISP
		}
	}
}

// routeTest evaluates the rule set for a (app, host, port) tuple and then dials
// a URL through the resolved route, reporting the real exit IP, country and
// latency. Live counterpart to /api/rules/test.
func (s *Server) routeTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		App, User, Host, IP, Protocol, URL string
		Port                               int
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, 400, err)
		return
	}
	if in.Host == "" && in.URL == "" {
		writeErr(w, 400, fmt.Errorf("host or url is required"))
		return
	}
	if in.URL == "" {
		in.URL = "https://api.ipify.org/?format=text"
	}
	if in.Port == 0 {
		in.Port = 443
	}
	host := strings.ToLower(in.Host)
	c := rules.Conn{App: in.App, User: in.User, Host: host, Port: in.Port, Proto: in.Protocol, UID: -1}
	if in.IP != "" {
		c.IP = rules.ResolveIP(in.IP)
	} else if host != "" {
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			c.IP, _ = netip.AddrFromSlice(ips[0])
			c.IP = c.IP.Unmap()
		}
	}
	if c.Proto == "" {
		c.Proto = "tcp"
	}
	d := s.d.Proxy.Evaluate(c)
	out := map[string]interface{}{
		"matched": d.Matched, "action": string(d.Action), "proxy": d.Proxy, "vpn": d.VPN,
	}
	if d.Matched && d.Rule != nil {
		out["rule"] = d.Rule.Name
		out["index"] = d.Index
	}
	cfg := s.d.Store.Get()
	route := upstream.Route{Action: d.Action, Proxy: d.Proxy, VPN: d.VPN}
	switch d.Action {
	case config.ActionBlock:
		out["blocked"] = true
		writeJSON(w, out)
		return
	case config.ActionIntercept:
		up := cfg.Intercept.Upstream
		route = upstream.Route{Action: up.Action, Proxy: up.Proxy, VPN: up.VPN}
		out["note"] = "intercept: probed via the intercept upstream route"
	case config.ActionDirect, "":
		route = upstream.Route{Action: config.ActionDirect}
	}
	if route.Action == config.ActionProxy && route.Proxy != "" {
		if hops, err := s.d.Dialer.Hops(route.Proxy); err == nil {
			names := make([]string, 0, len(hops))
			for _, hp := range hops {
				names = append(names, hp.Name)
			}
			out["hops"] = names
		}
	}
	s.dialThroughRoute(route, in.URL, out)
	writeJSON(w, out)
}

// routeProbe dials a URL through an ad-hoc, unsaved chain of hops (VPNs and
// proxies, in order). It registers a transient chain proxy, probes, and removes
// it — so the RouteBuilder can test a chain before it is saved.
func (s *Server) routeProbe(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hops []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"hops"`
		Host, URL string
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, 400, err)
		return
	}
	if in.URL == "" {
		in.URL = "https://api.ipify.org/?format=text"
	}
	var vpnHops, proxyHops []string
	for _, h := range in.Hops {
		switch h.Kind {
		case "vpn":
			vpnHops = append(vpnHops, h.Name)
		case "proxy":
			proxyHops = append(proxyHops, h.Name)
		}
	}
	out := map[string]interface{}{"vpn": "", "hops": proxyHops}
	if len(vpnHops) == 1 {
		out["vpn"] = vpnHops[0]
	}
	if len(vpnHops) >= 2 {
		out["ok"] = false
		out["error"] = "cannot live-test 2+ VPNs on the fly — create the route (full, nested tunnels) and bring the VPNs up in order, then use Rules → Live test"
		writeJSON(w, out)
		return
	}

	var route upstream.Route
	switch {
	case len(proxyHops) >= 1:
		if len(proxyHops) == 1 && len(vpnHops) == 0 {
			route = upstream.Route{Action: config.ActionProxy, Proxy: proxyHops[0]}
		} else {
			const transient = "__probe"
			chain := config.Proxy{Name: transient, Type: config.ProxyChain, Hops: proxyHops, RemoteDNS: true}
			if len(vpnHops) == 1 {
				chain.ViaVPN = vpnHops[0]
			}
			s.d.Dialer.SetExtraProxy(chain)
			defer s.d.Dialer.RemoveExtraProxy(transient)
			route = upstream.Route{Action: config.ActionProxy, Proxy: transient}
		}
	case len(vpnHops) == 1:
		route = upstream.Route{Action: config.ActionVPN, VPN: vpnHops[0]}
	default:
		route = upstream.Route{Action: config.ActionDirect}
	}
	s.dialThroughRoute(route, in.URL, out)
	writeJSON(w, out)
}
