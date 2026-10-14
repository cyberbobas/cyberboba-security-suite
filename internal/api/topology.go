package api

import (
	"net/http"

	"cyberboba/internal/config"
	"cyberboba/internal/topology"
)

func (s *Server) topoRoutes() {
	m := s.mux
	m.HandleFunc("GET /api/topology", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.buildTopology())
	})
	m.HandleFunc("GET /api/map", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.buildMap())
	})
	m.HandleFunc("POST /api/route/test", s.routeTest)
	m.HandleFunc("POST /api/route/probe", s.routeProbe)
	s.appsRoutes()
	s.firewallRoutes()
	s.rotationRoutes()
	m.HandleFunc("GET /api/geo/{ip}", func(w http.ResponseWriter, r *http.Request) {
		ip := r.PathValue("ip")
		info, err := s.d.Geo.LookupNow(ip)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, info)
	})
}

func (s *Server) buildTopology() topology.Graph {
	cfg := s.d.Store.Get()
	limit := 500
	conns := s.d.Tracker.List(limit, false)
	b := &topology.Builder{
		Hops: func(name string) ([]config.Proxy, error) { return s.d.Dialer.Hops(name) },
		Geo:  s.d.Geo,
	}
	interceptOn := s.d.Icpt != nil && cfg.Intercept.Enabled
	return b.Build(cfg, s.d.VPN.All(), conns, interceptOn)
}

func (s *Server) buildMap() topology.MapView {
	cfg := s.d.Store.Get()
	conns := s.d.Tracker.List(500, false)
	b := &topology.Builder{
		Hops: func(name string) ([]config.Proxy, error) { return s.d.Dialer.Hops(name) },
		Geo:  s.d.Geo,
	}
	return b.BuildMap(conns, cfg.Firewall.BlockedHosts)
}
