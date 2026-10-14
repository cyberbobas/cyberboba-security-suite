package api

import (
	"io"
	"net/http"

	"cyberboba/internal/client"
	"cyberboba/internal/mcp"
)

// handleMCP serves MCP over Streamable HTTP. Each POST body is a JSON-RPC
// request (or batch); the response is returned as JSON, or 202 for a pure
// notification. The MCP server talks back to this daemon over its own unix
// socket (or loopback) so all tools/resources reuse the HTTP API.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if s.mcp == nil {
		s.mcp = s.newLoopbackMCP()
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	resp, has := s.mcp.HandleHTTP(body)
	if !has {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// newLoopbackMCP builds an MCP server whose API client points back at this
// daemon's unix socket (preferred) or TCP listener.
func (s *Server) newLoopbackMCP() *mcp.Server {
	cfg := s.d.Store.Get()
	sock := cfg.API.UnixSocket
	addr := ""
	token := ""
	if sock == "" {
		addr = cfg.API.Listen
		token = cfg.API.Token
	}
	return mcp.New(client.New(sock, addr, token))
}
