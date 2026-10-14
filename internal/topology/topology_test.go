package topology

import (
	"testing"

	"cyberboba/internal/config"
	"cyberboba/internal/geo"
	"cyberboba/internal/stats"
	"cyberboba/internal/vpn"
)

func TestBuildChainsVPNAndProxy(t *testing.T) {
	cfg := config.Default()
	cfg.Proxies = []config.Proxy{
		{Name: "p1", Type: config.ProxySOCKS5, Addr: "1.1.1.1:1080", ViaVPN: "office"},
		{Name: "p2", Type: config.ProxyHTTP, Addr: "2.2.2.2:8080"},
		{Name: "dbl", Type: config.ProxyChain, Hops: []string{"p1", "p2"}},
	}
	cfg.VPNs = []config.VPN{
		{Name: "office", Type: config.VPNWireGuard, Config: "x", Mode: config.VPNModeSelective},
	}
	cfg.Rules = []config.Rule{
		{Name: "work", Apps: []string{"curl"}, Action: config.ActionProxy, Proxy: "dbl"},
		{Name: "block ads", Targets: []string{"ads.example.com"}, Action: config.ActionBlock},
		{Name: "Default", Action: config.ActionDirect},
	}

	hops := func(name string) ([]config.Proxy, error) {
		byName := map[string]config.Proxy{}
		for _, p := range cfg.Proxies {
			byName[p.Name] = p
		}
		p := byName[name]
		if p.Type == config.ProxyChain {
			var out []config.Proxy
			for i, h := range p.Hops {
				hp := byName[h]
				if i == 0 && p.ViaVPN != "" && hp.ViaVPN == "" {
					hp.ViaVPN = p.ViaVPN
				}
				out = append(out, hp)
			}
			return out, nil
		}
		return []config.Proxy{p}, nil
	}

	b := &Builder{Hops: hops, Geo: geo.New(false, "", 0, nil, nil)}
	up := vpn.Status{Name: "office", Type: config.VPNWireGuard, State: vpn.StateUp, Endpoint: "203.0.113.9:51820", Mode: config.VPNModeSelective}
	conns := []stats.Conn{
		{ID: 1, App: "curl", Host: "example.com", DstIP: "93.184.216.34", DstPort: 443, Action: "proxy", Via: "dbl", State: stats.StateOpen},
	}
	g := b.Build(cfg, []vpn.Status{up}, conns, true)

	// the "work" path must traverse: this -> vpn:office -> proxy:p1 -> proxy:p2 -> internet
	var work *Path
	for i := range g.Paths {
		if g.Paths[i].Rule == "work" {
			work = &g.Paths[i]
		}
	}
	if work == nil {
		t.Fatal("no work path")
	}
	want := []string{"this", "vpn:office", "proxy:p1", "proxy:p2", "internet"}
	if len(work.Nodes) != len(want) {
		t.Fatalf("work path = %v", work.Nodes)
	}
	for i := range want {
		if work.Nodes[i] != want[i] {
			t.Fatalf("work path = %v want %v", work.Nodes, want)
		}
	}

	// the live connection chain should end at the destination node
	if len(g.Live) != 1 {
		t.Fatalf("live=%d", len(g.Live))
	}
	lv := g.Live[0]
	if lv.Nodes[0] != "this" || lv.Nodes[len(lv.Nodes)-1] != "dst:example.com" {
		t.Fatalf("live chain = %v", lv.Nodes)
	}

	// vpn node present and marked up
	var hasVPN, hasBlocked, hasDest bool
	for _, n := range g.Nodes {
		switch n.ID {
		case "vpn:office":
			hasVPN = n.Up && n.State == "up"
		case "blocked":
			hasBlocked = true
		case "dst:example.com":
			hasDest = n.Conns == 1
		}
	}
	if !hasVPN {
		t.Fatal("vpn node missing/not up")
	}
	if !hasBlocked {
		t.Fatal("blocked node missing (block rule present)")
	}
	if !hasDest {
		t.Fatal("dest node missing or wrong conn count")
	}

	// an active edge should exist from this -> vpn:office
	var activeEdge bool
	for _, e := range g.Edges {
		if e.From == "this" && e.To == "vpn:office" && e.Active {
			activeEdge = true
		}
	}
	if !activeEdge {
		t.Fatal("expected active edge this->vpn:office from live conn")
	}
}
