package mcp

import (
	"fmt"
	"strconv"
	"strings"
)

type resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType"`
}

func (s *Server) resources() []resource {
	return []resource{
		{"cyberboba://status", "status", "Live daemon status (proxify, stats, VPNs, intercept)", "application/json"},
		{"cyberboba://config", "config", "Full configuration (YAML)", "application/yaml"},
		{"cyberboba://rules", "rules", "Ordered routing rules", "application/json"},
		{"cyberboba://proxies", "proxies", "Upstream proxies and groups", "application/json"},
		{"cyberboba://vpns", "vpns", "VPN profiles with live state", "application/json"},
		{"cyberboba://connections", "connections", "Live and recent connections", "application/json"},
		{"cyberboba://flows", "flows", "Last 100 intercepted HTTP flows", "application/json"},
		{"cyberboba://topology", "topology", "Traffic map: nodes, edges, per-rule paths and live connections with geo", "application/json"},
		{"cyberboba://ca.crt", "ca", "Intercept CA certificate (PEM)", "application/x-pem-file"},
		{"cyberboba://openapi", "openapi", "OpenAPI specification of the HTTP API", "application/json"},
	}
}

func (s *Server) resourceTemplates() []map[string]interface{} {
	return []map[string]interface{}{
		{"uriTemplate": "cyberboba://flows/{id}", "name": "flow", "description": "One flow with bodies and raw text", "mimeType": "application/json"},
		{"uriTemplate": "cyberboba://flows/{id}/request", "name": "flow-request", "description": "Raw HTTP request of a flow", "mimeType": "text/plain"},
		{"uriTemplate": "cyberboba://flows/{id}/response", "name": "flow-response", "description": "Raw HTTP response of a flow", "mimeType": "text/plain"},
	}
}

func (s *Server) readResource(uri string) ([]map[string]interface{}, error) {
	text := func(mime, body string) []map[string]interface{} {
		return []map[string]interface{}{{"uri": uri, "mimeType": mime, "text": body}}
	}
	raw := func(path string) (string, error) {
		b, err := s.c.Do("GET", path, nil)
		return string(b), err
	}
	switch {
	case uri == "cyberboba://status":
		b, err := raw("/api/status")
		return text("application/json", b), err
	case uri == "cyberboba://config":
		b, err := raw("/api/config/yaml")
		return text("application/yaml", b), err
	case uri == "cyberboba://rules":
		b, err := raw("/api/rules")
		return text("application/json", b), err
	case uri == "cyberboba://proxies":
		b, err := raw("/api/proxies")
		return text("application/json", b), err
	case uri == "cyberboba://vpns":
		b, err := raw("/api/vpn")
		return text("application/json", b), err
	case uri == "cyberboba://connections":
		b, err := raw("/api/connections?limit=200")
		return text("application/json", b), err
	case uri == "cyberboba://flows":
		b, err := raw("/api/intercept/flows?limit=100")
		return text("application/json", b), err
	case uri == "cyberboba://topology":
		b, err := raw("/api/topology")
		return text("application/json", b), err
	case uri == "cyberboba://ca.crt":
		b, err := raw("/api/intercept/ca")
		return text("application/x-pem-file", b), err
	case uri == "cyberboba://openapi":
		b, err := raw("/api/openapi.json")
		return text("application/json", b), err
	case strings.HasPrefix(uri, "cyberboba://flows/"):
		rest := strings.TrimPrefix(uri, "cyberboba://flows/")
		parts := strings.Split(rest, "/")
		id := parts[0]
		if _, err := strconv.Atoi(id); err != nil {
			return nil, fmt.Errorf("bad flow id %q", id)
		}
		if len(parts) == 1 {
			b, err := raw("/api/intercept/flows/" + id)
			return text("application/json", b), err
		}
		var field string
		switch parts[1] {
		case "request":
			field = "req_raw"
		case "response":
			field = "resp_raw"
		default:
			return nil, fmt.Errorf("unknown flow sub-resource %q", parts[1])
		}
		var d map[string]interface{}
		if err := s.c.JSON("GET", "/api/intercept/flows/"+id, nil, &d); err != nil {
			return nil, err
		}
		body, _ := d[field].(string)
		return text("text/plain", body), nil
	}
	return nil, fmt.Errorf("unknown resource %q", uri)
}

// --- prompts ---

type promptArg struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

func (s *Server) prompts() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "route_app", "description": "Route a named application through a proxy or VPN, then verify",
			"arguments": []promptArg{{"app", "process name, e.g. firefox", true}, {"via", "proxy or vpn target", false}}},
		{"name": "capture_traffic", "description": "Set up TLS interception for an application and inspect its HTTP flows",
			"arguments": []promptArg{{"app", "process name", true}, {"scope", "host pattern to focus on, e.g. *.example.com", false}}},
		{"name": "analyze_flows", "description": "Review captured flows for a host and summarize interesting requests",
			"arguments": []promptArg{{"host", "hostname to analyze", true}}},
	}
}

func (s *Server) getPrompt(name string, args map[string]string) (map[string]interface{}, error) {
	msg := func(text string) map[string]interface{} {
		return map[string]interface{}{
			"messages": []map[string]interface{}{
				{"role": "user", "content": map[string]interface{}{"type": "text", "text": text}},
			},
		}
	}
	app := args["app"]
	switch name {
	case "route_app":
		via := args["via"]
		return msg(fmt.Sprintf("Using the cyberboba tools, route the application %q through %q.\n"+
			"1. Call list_processes to confirm the exact process name.\n"+
			"2. If %q names a proxy, ensure it exists (list_proxies, add_proxy) and check_proxy it. If it names a VPN, vpn_up it.\n"+
			"3. add_rule placing an apps:[%q] rule with the right action (proxy/vpn) above the catch-all.\n"+
			"4. test_rule for the app against a representative host, then list_connections to confirm live traffic uses it.\n"+
			"Report the exit IP or tunnel used.", app, via, via, app)), nil
	case "capture_traffic":
		scope := args["scope"]
		sc := scope
		if sc == "" {
			sc = "(all hosts)"
		}
		return msg(fmt.Sprintf("Capture %q's HTTPS traffic with cyberboba's interceptor.\n"+
			"1. install_ca (once) so the app trusts the intercept CA.\n"+
			"2. If a scope is useful, intercept_configure scope_include=[%q].\n"+
			"3. add_rule apps:[%q] ports:[80,443] action:intercept above the catch-all.\n"+
			"4. Have the app make requests, then list_flows (filter host=%s) and get_flow on the interesting ones.\n"+
			"Summarize endpoints, auth headers and any tokens you see.", app, scope, app, sc)), nil
	case "analyze_flows":
		host := args["host"]
		if host == "" {
			return nil, fmt.Errorf("argument 'host' is required")
		}
		return msg(fmt.Sprintf("Analyze captured cyberboba flows for host %q.\n"+
			"1. list_flows host=%q (and body=... to search payloads).\n"+
			"2. get_flow on notable ids to read headers and bodies.\n"+
			"3. Group by endpoint/method, note status codes, auth, and anything sensitive.\n"+
			"Produce a short findings list with flow ids.", host, host)), nil
	}
	return nil, fmt.Errorf("unknown prompt %q", name)
}
