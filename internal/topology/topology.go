// Package topology turns the live routing reality (config + VPN state + active
// connections) into a graph the UI can draw: nodes (this machine, VPNs,
// proxies, destinations) and the ordered path each connection or rule takes
// through them. It is the data behind the "Traffic" map tab.
package topology

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"cyberboba/internal/config"
	"cyberboba/internal/geo"
	"cyberboba/internal/stats"
	"cyberboba/internal/vpn"
)

// Node is a point in the graph.
type Node struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"` // client|intercept|vpn|proxy|dest|internet|blocked
	Label    string `json:"label"`
	Detail   string `json:"detail,omitempty"`
	State    string `json:"state,omitempty"`
	Type     string `json:"type,omitempty"`
	Addr     string `json:"addr,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Country  string `json:"country,omitempty"`
	CC       string `json:"cc,omitempty"`
	City     string `json:"city,omitempty"`
	Flag     string `json:"flag,omitempty"`
	Conns    int    `json:"conns,omitempty"`
	BytesIn  int64  `json:"bytes_in,omitempty"`
	BytesOut int64  `json:"bytes_out,omitempty"`
	Up       bool   `json:"up,omitempty"`
}

// Edge connects two nodes.
type Edge struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Kind     string   `json:"kind,omitempty"` // route|hop|via_vpn|block|direct
	Rules    []string `json:"rules,omitempty"`
	Conns    int      `json:"active_conns,omitempty"`
	BytesIn  int64    `json:"bytes_in,omitempty"`
	BytesOut int64    `json:"bytes_out,omitempty"`
	Active   bool     `json:"active,omitempty"`
}

// Path is the ordered chain of node ids a rule's traffic traverses.
type Path struct {
	Rule    string   `json:"rule"`
	Action  string   `json:"action"`
	Match   string   `json:"match"`
	Nodes   []string `json:"nodes"`
	Enabled bool     `json:"enabled"`
}

// Live is a current connection with its computed chain and destination geo.
type Live struct {
	ID       uint64   `json:"id"`
	App      string   `json:"app"`
	Host     string   `json:"host"`
	DstIP    string   `json:"dst_ip"`
	Port     int      `json:"dst_port"`
	Action   string   `json:"action"`
	Via      string   `json:"via,omitempty"`
	VPN      string   `json:"vpn,omitempty"`
	Country  string   `json:"country,omitempty"`
	CC       string   `json:"cc,omitempty"`
	Flag     string   `json:"flag,omitempty"`
	Nodes    []string `json:"nodes"`
	State    string   `json:"state"`
	BytesIn  int64    `json:"bytes_in"`
	BytesOut int64    `json:"bytes_out"`
}

// Graph is the full topology.
type Graph struct {
	Nodes       []Node    `json:"nodes"`
	Edges       []Edge    `json:"edges"`
	Paths       []Path    `json:"paths"`
	Live        []Live    `json:"live"`
	GeoEnabled  bool      `json:"geo_enabled"`
	GeneratedAt time.Time `json:"generated_at"`
}

// HopsFunc expands a proxy/chain name into the ordered concrete hops.
type HopsFunc func(name string) ([]config.Proxy, error)

// Builder assembles graphs from the daemon's state.
type Builder struct {
	Hops HopsFunc
	Geo  *geo.Cache
}

const (
	nodeThis     = "this"
	nodeInternet = "internet"
	nodeBlocked  = "blocked"
	nodeIntercpt = "intercept"
)

func vpnID(name string) string   { return "vpn:" + name }
func proxyID(name string) string { return "proxy:" + name }

func destID(host, ip string) string {
	if host != "" {
		return "dst:" + strings.ToLower(host)
	}
	if ip != "" {
		return "dst:" + ip
	}
	return nodeInternet
}

// Build produces the graph. interceptOn reflects whether the intercept engine
// is running (so the model can show the MITM hop).
func (b *Builder) Build(cfg *config.Config, vpns []vpn.Status, conns []stats.Conn, interceptOn bool) Graph {
	g := Graph{GeneratedAt: time.Now(), GeoEnabled: b.Geo.Enabled()}

	nodes := map[string]*Node{}
	order := []string{}
	addNode := func(n Node) *Node {
		if ex, ok := nodes[n.ID]; ok {
			return ex
		}
		cp := n
		nodes[n.ID] = &cp
		order = append(order, n.ID)
		return &cp
	}

	me := addNode(Node{ID: nodeThis, Kind: "client", Label: "this machine", Detail: hostname()})
	_ = me
	addNode(Node{ID: nodeInternet, Kind: "internet", Label: "internet"})

	vpnByName := map[string]vpn.Status{}
	for _, v := range vpns {
		vpnByName[v.Name] = v
	}

	// VPN nodes: every profile that is up, plus any referenced below.
	ensureVPN := func(name string) {
		if name == "" {
			return
		}
		id := vpnID(name)
		if _, ok := nodes[id]; ok {
			return
		}
		st := vpnByName[name]
		n := Node{ID: id, Kind: "vpn", Label: name, Type: string(st.Type), State: string(st.State),
			Mode: string(st.Mode), Up: st.State == vpn.StateUp}
		if ep := hostOnly(st.Endpoint); ep != "" {
			n.Addr = st.Endpoint
			b.geoInto(ep, &n)
		}
		addNode(n)
	}
	for _, v := range vpns {
		if v.State == vpn.StateUp || v.State == vpn.StateConnecting {
			ensureVPN(v.Name)
		}
	}

	proxyByName := map[string]config.Proxy{}
	for _, p := range cfg.Proxies {
		proxyByName[p.Name] = p
	}
	ensureProxy := func(name string) {
		if name == "" {
			return
		}
		id := proxyID(name)
		if _, ok := nodes[id]; ok {
			return
		}
		p := proxyByName[name]
		n := Node{ID: id, Kind: "proxy", Label: name, Type: string(p.Type), Addr: p.Addr}
		if h := hostOnly(p.Addr); h != "" {
			b.geoInto(h, &n)
		}
		addNode(n)
		if p.ViaVPN != "" {
			ensureVPN(p.ViaVPN)
		}
	}

	// chain builds the ordered node ids for an action/proxy/vpn triple, ending
	// at terminal (a dst id or "internet"/"blocked").
	chain := func(action, proxyName, vpnName, terminal string) ([]string, bool) {
		out := []string{nodeThis}
		if interceptOn && action == string(config.ActionIntercept) {
			out = append(out, nodeIntercpt)
		}
		ok := true
		switch config.Action(action) {
		case config.ActionBlock:
			return append(out, nodeBlocked), true
		case config.ActionVPN:
			ensureVPN(vpnName)
			if vpnName != "" {
				out = append(out, vpnID(vpnName))
			}
		case config.ActionProxy:
			hops, err := expandHops(b.Hops, proxyName)
			if err != nil || len(hops) == 0 {
				ensureProxy(proxyName)
				out = append(out, proxyID(proxyName))
				ok = false
			} else {
				for i, h := range hops {
					if i == 0 && h.ViaVPN != "" {
						ensureVPN(h.ViaVPN)
						out = append(out, vpnID(h.ViaVPN))
					}
					ensureProxy(h.Name)
					out = append(out, proxyID(h.Name))
				}
			}
		case config.ActionIntercept:
			// intercept terminates locally; upstream continues per config.
			up := cfg.Intercept.Upstream
			if up.Action == config.ActionVPN && up.VPN != "" {
				ensureVPN(up.VPN)
				out = append(out, vpnID(up.VPN))
			} else if up.Action == config.ActionProxy && up.Proxy != "" {
				hops, err := expandHops(b.Hops, up.Proxy)
				if err == nil {
					for _, h := range hops {
						ensureProxy(h.Name)
						out = append(out, proxyID(h.Name))
					}
				}
			}
		}
		out = append(out, terminal)
		return out, ok
	}

	// Per-rule logical paths.
	hasBlock := false
	for _, r := range cfg.Rules {
		terminal := nodeInternet
		if r.Action == config.ActionBlock {
			terminal = nodeBlocked
			hasBlock = true
		}
		path, _ := chain(string(r.Action), r.Proxy, r.VPN, terminal)
		g.Paths = append(g.Paths, Path{
			Rule: r.Name, Action: string(r.Action), Match: matchSummary(r),
			Nodes: path, Enabled: r.IsEnabled(),
		})
	}
	if hasBlock {
		addNode(Node{ID: nodeBlocked, Kind: "blocked", Label: "blocked"})
	}
	if interceptOn {
		addNode(Node{ID: nodeIntercpt, Kind: "intercept", Label: "intercept"})
	}

	// Edges: aggregate from enabled rule paths.
	edges := map[string]*Edge{}
	edgeKey := func(a, b string) string { return a + "\x00" + b }
	addEdge := func(a, bn, kind, rule string) *Edge {
		k := edgeKey(a, bn)
		e, ok := edges[k]
		if !ok {
			e = &Edge{From: a, To: bn, Kind: kind}
			edges[k] = e
		}
		if rule != "" && !contains(e.Rules, rule) {
			e.Rules = append(e.Rules, rule)
		}
		return e
	}
	for _, p := range g.Paths {
		if !p.Enabled {
			continue
		}
		kind := "route"
		for i := 0; i+1 < len(p.Nodes); i++ {
			addEdge(p.Nodes[i], p.Nodes[i+1], kind, p.Rule)
		}
	}

	// Live connections: compute chain + destination geo, accumulate on nodes/edges.
	destAgg := map[string]*Node{}
	for i := range conns {
		c := &conns[i]
		terminal := nodeInternet
		if c.Action == string(config.ActionBlock) || c.State == stats.StateBlocked {
			terminal = nodeBlocked
			addNode(Node{ID: nodeBlocked, Kind: "blocked", Label: "blocked"})
		} else {
			terminal = destID(c.Host, c.DstIP)
		}
		path, _ := chain(c.Action, c.Via, c.VPN, terminal)

		lv := Live{ID: c.ID, App: c.App, Host: c.Host, DstIP: c.DstIP, Port: c.DstPort,
			Action: c.Action, Via: c.Via, VPN: c.VPN, Nodes: path, State: string(c.State),
			BytesIn: c.BytesIn, BytesOut: c.BytesOut}

		// destination node + geo
		if terminal != nodeBlocked && terminal != nodeInternet {
			dn, ok := destAgg[terminal]
			if !ok {
				label := c.Host
				if label == "" {
					label = c.DstIP
				}
				n := &Node{ID: terminal, Kind: "dest", Label: label, Addr: c.DstIP}
				if c.DstIP != "" {
					b.geoInto(c.DstIP, n)
				} else if c.Host != "" {
					b.geoInto(c.Host, n)
				}
				destAgg[terminal] = n
				dn = n
			}
			dn.Conns++
			dn.BytesIn += c.BytesIn
			dn.BytesOut += c.BytesOut
			lv.Country, lv.CC, lv.Flag = dn.Country, dn.CC, dn.Flag
		}

		if c.State == stats.StateOpen {
			for j := 0; j+1 < len(path); j++ {
				e := addEdge(path[j], path[j+1], "route", "")
				e.Conns++
				e.Active = true
				e.BytesIn += c.BytesIn
				e.BytesOut += c.BytesOut
			}
			// node byte/conn accounting for hops
			for _, id := range path {
				if n, ok := nodes[id]; ok {
					n.BytesIn += c.BytesIn
					n.BytesOut += c.BytesOut
				}
			}
		}
		g.Live = append(g.Live, lv)
	}
	for id, dn := range destAgg {
		if _, ok := nodes[id]; !ok {
			addNode(*dn)
		} else {
			nodes[id] = dn
		}
	}

	// emit nodes in insertion order
	for _, id := range order {
		g.Nodes = append(g.Nodes, *nodes[id])
	}
	// any dest nodes not already in order
	seen := map[string]bool{}
	for _, id := range order {
		seen[id] = true
	}
	ids := make([]string, 0, len(destAgg))
	for id := range destAgg {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		g.Nodes = append(g.Nodes, *destAgg[id])
	}

	for _, e := range edges {
		g.Edges = append(g.Edges, *e)
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		return g.Edges[i].To < g.Edges[j].To
	})
	return g
}

func (b *Builder) geoInto(addr string, n *Node) {
	if b.Geo == nil {
		return
	}
	if info, ok := b.Geo.Lookup(addr); ok {
		n.Country, n.CC, n.City, n.Flag = info.Country, info.CC, info.City, info.Flag
	}
}

func expandHops(h HopsFunc, name string) ([]config.Proxy, error) {
	if h == nil || name == "" {
		return nil, fmt.Errorf("no hops")
	}
	return h(name)
}

func matchSummary(r config.Rule) string {
	var parts []string
	if len(r.Apps) > 0 {
		parts = append(parts, "apps="+strings.Join(r.Apps, ","))
	}
	if len(r.Targets) > 0 {
		parts = append(parts, "to="+strings.Join(r.Targets, ","))
	}
	if len(r.Ports) > 0 {
		parts = append(parts, "ports="+strings.Join(r.Ports, ","))
	}
	if len(r.Users) > 0 {
		parts = append(parts, "users="+strings.Join(r.Users, ","))
	}
	if len(parts) == 0 {
		return "any"
	}
	return strings.Join(parts, " ")
}

func hostOnly(addr string) string {
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func hostname() string {
	n, _ := os.Hostname()
	return n
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
