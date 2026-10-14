package api

import "net/http"

func (s *Server) bandwidthRoutes() {
	m := s.mux

	// Live per-application bandwidth: up/down speed, session totals and
	// persisted today / rolling-30-day data usage (GlassWire-style).
	m.HandleFunc("GET /api/bandwidth", func(w http.ResponseWriter, r *http.Request) {
		if s.d.Bandwidth == nil {
			writeJSON(w, map[string]interface{}{"apps": []interface{}{}})
			return
		}
		writeJSON(w, s.d.Bandwidth.Snapshot())
	})

	// Per-day totals (last ~month), newest first.
	m.HandleFunc("GET /api/bandwidth/daily", func(w http.ResponseWriter, r *http.Request) {
		days := []map[string]interface{}{}
		if s.d.Bandwidth != nil {
			days = s.d.Bandwidth.Daily()
		}
		writeJSON(w, map[string]interface{}{"days": days})
	})

	// Recent "abnormal data transfer" alerts (newest first) and the active
	// detector config. An app trips an alert when its live upload/download
	// rate runs far over its own recent baseline and above an absolute floor.
	m.HandleFunc("GET /api/bandwidth/alerts", func(w http.ResponseWriter, r *http.Request) {
		if s.d.Bandwidth == nil {
			writeJSON(w, map[string]interface{}{"alerts": []interface{}{}, "config": map[string]interface{}{}})
			return
		}
		alerts, cfg := s.d.Bandwidth.Alerts()
		writeJSON(w, map[string]interface{}{"alerts": alerts, "config": cfg})
	})

	// Clear all session and persisted usage history.
	m.HandleFunc("POST /api/bandwidth/reset", func(w http.ResponseWriter, r *http.Request) {
		if s.d.Bandwidth != nil {
			s.d.Bandwidth.Reset()
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
}
