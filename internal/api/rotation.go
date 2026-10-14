package api

import (
	"net/http"

	"cyberboba/internal/config"
)

func (s *Server) rotationRoutes() {
	m := s.mux
	// live proxy-rotation state (current member, next switch countdown)
	m.HandleFunc("GET /api/proxies/rotation", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"rotations": s.d.Dialer.RotationStates()})
	})
	// VPN rotations: config + live state
	m.HandleFunc("GET /api/vpn/rotations", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"rotations": s.d.Store.Get().VPNRotations,
			"status":    s.d.VPNRot.Status(),
		})
	})
	m.HandleFunc("PUT /api/vpn/rotations", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Rotations []config.VPNRotation `json:"rotations"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := s.d.Store.Mutate(func(c *config.Config) error { c.VPNRotations = in.Rotations; return nil }); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, map[string]interface{}{
			"rotations": s.d.Store.Get().VPNRotations,
			"status":    s.d.VPNRot.Status(),
		})
	})
}
