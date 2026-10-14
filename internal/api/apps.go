package api

import (
	"net/http"

	"cyberboba/internal/apps"
)

func (s *Server) appsRoutes() {
	s.mux.HandleFunc("GET /api/apps/installed", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"apps": apps.List()})
	})
}
