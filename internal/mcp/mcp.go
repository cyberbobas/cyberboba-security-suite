// Package mcp implements a Model Context Protocol server (stdio transport)
// that exposes cyberboba to AI agents as a set of tools. Every tool is a thin
// wrapper over the daemon's HTTP API.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyberboba/internal/client"
)

// Version reported in serverInfo.
var Version = "0.2.0"

const protocolVersion = "2025-06-18"

// Server is the MCP server.
type Server struct {
	c     *client.Client
	tools []tool
	out   io.Writer
	wmu   sync.Mutex
	log   io.Writer
	wg    sync.WaitGroup
}

type tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
	run         func(args map[string]interface{}) (interface{}, error)
}

// New creates a server bound to an API client.
func New(c *client.Client) *Server {
	s := &Server{c: c, out: os.Stdout, log: os.Stderr}
	s.register()
	return s
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Serve reads newline-delimited JSON-RPC from r until EOF.
func (s *Server) Serve(r io.Reader) error {
	// Push resource-updated and log notifications from the daemon event
	// stream to the stdio client (best effort; ignored by clients that do
	// not support notifications).
	go s.streamNotifications()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(req)
		}()
	}
	s.wg.Wait()
	return sc.Err()
}

func (s *Server) send(resp response) {
	b, _ := json.Marshal(resp)
	s.wmu.Lock()
	s.out.Write(append(b, '\n'))
	s.wmu.Unlock()
}

func (s *Server) handle(req request) {
	resp, ok := s.dispatch(req)
	if ok {
		s.send(resp)
	}
}

// dispatch processes one request and returns the response plus whether a
// response should be sent (false for notifications).
func (s *Server) dispatch(req request) (response, bool) {
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"
	var out response
	sent := false
	reply := func(result interface{}, err *rpcError) {
		if isNotification {
			return
		}
		out = response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: err}
		sent = true
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		pv := protocolVersion
		if p.ProtocolVersion == "2024-11-05" || p.ProtocolVersion == "2025-03-26" {
			pv = p.ProtocolVersion
		}
		reply(map[string]interface{}{
			"protocolVersion": pv,
			"capabilities": map[string]interface{}{
				"tools":     map[string]interface{}{"listChanged": false},
				"resources": map[string]interface{}{"subscribe": false, "listChanged": false},
				"prompts":   map[string]interface{}{"listChanged": false},
				"logging":   map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{"name": "cyberboba", "version": Version},
			"instructions": "cyberboba controls the host's network: per-application routing rules (direct / proxy / vpn / intercept / block), " +
				"SOCKS/HTTP proxies and chains, WireGuard/OpenVPN tunnels, and an intercepting HTTP(S) proxy with history, " +
				"hold-and-edit, match & replace and a repeater. Start with `status` and `list_rules`. Rules are evaluated top to bottom, first match wins; " +
				"keep a final catch-all rule. Use `send_request` to replay/craft HTTP requests and `list_flows`/`get_flow` to read captured traffic. " +
				"Resources under cyberboba:// give live read-only views; prompts route_app/capture_traffic/analyze_flows are guided workflows.",
		}, nil)
	case "notifications/initialized", "notifications/cancelled", "notifications/progress":
		return out, false
	case "ping":
		reply(map[string]interface{}{}, nil)
	case "tools/list":
		reply(map[string]interface{}{"tools": s.tools}, nil)
	case "tools/call":
		var p struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			reply(nil, &rpcError{Code: -32602, Message: "invalid params"})
			break
		}
		found := false
		for _, t := range s.tools {
			if t.Name == p.Name {
				found = true
				if p.Arguments == nil {
					p.Arguments = map[string]interface{}{}
				}
				res, err := t.run(p.Arguments)
				if err != nil {
					reply(map[string]interface{}{"content": []map[string]string{{"type": "text", "text": "error: " + err.Error()}}, "isError": true}, nil)
					break
				}
				text, ok := res.(string)
				if !ok {
					b, _ := json.MarshalIndent(res, "", "  ")
					text = string(b)
				}
				reply(map[string]interface{}{"content": []map[string]string{{"type": "text", "text": text}}}, nil)
				break
			}
		}
		if !found {
			reply(nil, &rpcError{Code: -32602, Message: "unknown tool " + p.Name})
		}
	case "resources/list":
		reply(map[string]interface{}{"resources": s.resources()}, nil)
	case "resources/templates/list":
		reply(map[string]interface{}{"resourceTemplates": s.resourceTemplates()}, nil)
	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		_ = json.Unmarshal(req.Params, &p)
		contents, err := s.readResource(p.URI)
		if err != nil {
			reply(nil, &rpcError{Code: -32002, Message: err.Error()})
			break
		}
		reply(map[string]interface{}{"contents": contents}, nil)
	case "prompts/list":
		reply(map[string]interface{}{"prompts": s.prompts()}, nil)
	case "prompts/get":
		var p struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &p)
		res, err := s.getPrompt(p.Name, p.Arguments)
		if err != nil {
			reply(nil, &rpcError{Code: -32602, Message: err.Error()})
			break
		}
		reply(res, nil)
	case "logging/setLevel":
		reply(map[string]interface{}{}, nil)
	default:
		reply(nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method})
	}
	return out, sent
}

// HandleHTTP processes a single JSON-RPC message (or batch) given as raw
// bytes and returns the response bytes. nil return means "no response body"
// (notification only); the caller should answer 202.
func (s *Server) HandleHTTP(body []byte) ([]byte, bool) {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		var reqs []request
		if err := json.Unmarshal(body, &reqs); err != nil {
			b, _ := json.Marshal(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}})
			return b, true
		}
		var resps []response
		for _, req := range reqs {
			if resp, ok := s.dispatch(req); ok {
				resps = append(resps, resp)
			}
		}
		if len(resps) == 0 {
			return nil, false
		}
		b, _ := json.Marshal(resps)
		return b, true
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		b, _ := json.Marshal(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}})
		return b, true
	}
	resp, ok := s.dispatch(req)
	if !ok {
		return nil, false
	}
	b, _ := json.Marshal(resp)
	return b, true
}

// notify sends a JSON-RPC notification to the client.
func (s *Server) notify(method string, params interface{}) {
	b, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": method, "params": params})
	s.wmu.Lock()
	s.out.Write(append(b, '\n'))
	s.wmu.Unlock()
}

// streamNotifications follows the daemon SSE stream and forwards flow /
// connection updates as resources/updated and log lines as message
// notifications. It reconnects on error and never blocks the server.
func (s *Server) streamNotifications() {
	var lastFlow, lastConn time.Time
	for {
		err := s.c.Stream(context.Background(), func(typ string, data []byte) {
			now := time.Now()
			switch typ {
			case "flow":
				if now.Sub(lastFlow) < time.Second {
					return
				}
				lastFlow = now
				s.notify("notifications/resources/updated", map[string]string{"uri": "cyberboba://flows"})
			case "conn":
				if now.Sub(lastConn) < time.Second {
					return
				}
				lastConn = now
				s.notify("notifications/resources/updated", map[string]string{"uri": "cyberboba://connections"})
			case "log":
				var l struct {
					Level, Msg string
				}
				_ = json.Unmarshal(data, &l)
				lvl := l.Level
				if lvl == "" {
					lvl = "info"
				}
				s.notify("notifications/message", map[string]interface{}{"level": lvl, "logger": "cyberboba", "data": l.Msg})
			}
		})
		if err == nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// --- helpers ---

func boolArg(args map[string]interface{}, k string) bool {
	switch v := args[k].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1" || v == "yes"
	case float64:
		return v != 0
	}
	return false
}

func str(args map[string]interface{}, k string) string {
	if v, ok := args[k]; ok && v != nil {
		switch x := v.(type) {
		case string:
			return x
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(x)
		}
	}
	return ""
}

func num(args map[string]interface{}, k string) int {
	if v, ok := args[k]; ok && v != nil {
		switch x := v.(type) {
		case float64:
			return int(x)
		case string:
			n, _ := strconv.Atoi(x)
			return n
		}
	}
	return 0
}

func boolp(args map[string]interface{}, k string) *bool {
	if v, ok := args[k]; ok && v != nil {
		if b, ok := v.(bool); ok {
			return &b
		}
	}
	return nil
}

func list(args map[string]interface{}, k string) []string {
	v, ok := args[k]
	if !ok || v == nil {
		return nil
	}
	switch x := v.(type) {
	case []interface{}:
		var out []string
		for _, i := range x {
			out = append(out, fmt.Sprint(i))
		}
		return out
	case string:
		var out []string
		for _, p := range strings.Split(x, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}

func schema(props map[string]interface{}, required ...string) map[string]interface{} {
	m := map[string]interface{}{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func p(t, desc string) map[string]interface{} {
	return map[string]interface{}{"type": t, "description": desc}
}

func parr(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}, "description": desc}
}

func (s *Server) get(path string) (interface{}, error) {
	var v interface{}
	err := s.c.JSON("GET", path, nil, &v)
	return v, err
}

func (s *Server) post(method, path string, body interface{}) (interface{}, error) {
	var v interface{}
	err := s.c.JSON(method, path, body, &v)
	return v, err
}

func (s *Server) add(name, desc string, sch map[string]interface{}, run func(map[string]interface{}) (interface{}, error)) {
	s.tools = append(s.tools, tool{Name: name, Description: desc, InputSchema: sch, run: run})
}

// register defines the tool set.
func (s *Server) register() {
	// --- status / config ---
	s.add("status", "Daemon status: proxify state, traffic counters, VPN tunnels, intercept summary, warnings.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/status") })
	s.add("doctor", "Environment checks (root, iptables, wireguard, openvpn, CA, listeners).", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/doctor") })
	s.add("get_config", "Full configuration as YAML text.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) {
			b, err := s.c.Do("GET", "/api/config/yaml", nil)
			return string(b), err
		})
	s.add("set_config", "Replace the full configuration with YAML text (validated, saved, applied live).",
		schema(map[string]interface{}{"yaml": p("string", "complete configuration document")}, "yaml"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("PUT", "/api/config/yaml", str(a, "yaml"))
		})
	s.add("proxify", "Enable or disable transparent interception (iptables rules) at runtime.",
		schema(map[string]interface{}{"enabled": p("boolean", "true to install rules, false to remove")}, "enabled"),
		func(a map[string]interface{}) (interface{}, error) {
			if b := boolp(a, "enabled"); b != nil && !*b {
				return s.post("POST", "/api/proxify/disable", nil)
			}
			return s.post("POST", "/api/proxify/enable", nil)
		})
	s.add("log", "Recent daemon log lines.", schema(map[string]interface{}{"limit": p("integer", "max lines (default 200)")}),
		func(a map[string]interface{}) (interface{}, error) {
			n := num(a, "limit")
			if n == 0 {
				n = 200
			}
			return s.get("/api/log?limit=" + strconv.Itoa(n))
		})
	s.add("list_processes", "Running processes (name, exe, user) for building app rules.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/processes") })
	s.add("system_stats", "Host resource usage for the Processes header: overall and per-core CPU%, load averages, memory/swap usage, and every temperature (and fan) sensor the kernel exposes (CPU package/cores, chipset, etc.).", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/sysstat") })
	s.add("process_monitor", "Task-Manager view: every process with live CPU%, resident memory (rss_kb), owner, state, thread and active-connection counts, plus a `system` flag (kernel thread or uid<1000 service account). Sorted by CPU. Use it to see what is running and what is busy.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/procmon") })
	s.add("kill_process", "Send a signal to a process by pid (default TERM, or KILL to force). Refuses pid 1 and the cyberboba daemon itself.",
		schema(map[string]interface{}{"pid": p("integer", "process id"), "signal": p("string", "TERM (default) | KILL | HUP | INT")}, "pid"),
		func(a map[string]interface{}) (interface{}, error) {
			pid := num(a, "pid")
			if pid == 0 {
				return nil, fmt.Errorf("pid is required")
			}
			return s.post("POST", "/api/processes/"+strconv.Itoa(pid)+"/kill", map[string]interface{}{"signal": str(a, "signal")})
		})
	s.add("system_reclaim", "Free memory the system is holding when the box is sluggish: drops the page/inode cache (safe, default on), and optionally cycles swap back into RAM (swap:true — refused if it would not fit in free RAM) and compacts memory (compact:true). Returns how much RAM/swap was freed. Needs no app change; use it to relieve a growing swap file or cache pressure.",
		schema(map[string]interface{}{"caches": p("boolean", "drop page cache / dentries / inodes (default true)"), "swap": p("boolean", "swapoff -a && swapon -a to empty swap into RAM (default false)"), "compact": p("boolean", "defragment memory (default false)")}),
		func(a map[string]interface{}) (interface{}, error) {
			body := map[string]interface{}{"swap": boolArg(a, "swap"), "compact": boolArg(a, "compact")}
			if b := boolp(a, "caches"); b != nil {
				body["caches"] = *b
			}
			return s.post("POST", "/api/system/reclaim", body)
		})
	s.add("bandwidth_usage", "Per-application bandwidth (GlassWire-style): live download/upload speed (rate_in/rate_out bytes/sec), this-session totals, and persisted today / rolling-30-day data usage per app, plus active connection counts. Sorted by live speed. Use it to see which app is using the network right now and which has eaten the most data.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/bandwidth") })
	s.add("bandwidth_daily", "Per-day total bytes in/out for roughly the last month (data-usage history).", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/bandwidth/daily") })
	s.add("bandwidth_reset", "Clear all bandwidth usage history (session + persisted daily totals).", schema(nil),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/bandwidth/reset", nil)
		})
	s.add("bandwidth_alerts", "Recent 'application is sending/receiving an abnormal amount of data' alerts (newest first) plus the detector config. An alert fires when an app's live upload or download rate runs far over its own recent baseline and above an absolute floor — use it to catch a process suddenly exfiltrating or pulling data.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/bandwidth/alerts") })
	s.add("ai_agents", "AI-agent control centre: which known AI CLI/coding agents (Claude Code, Codex, Gemini, Cursor, Copilot, aider, ollama, …) are running, the API endpoints they contact, their live bandwidth, and — most importantly — any credentials/API keys/passwords they were seen sending off the box (credential-leak findings per agent). The headline security view over your AI tools.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/ai") })
	s.add("ai_agent_log", "Recent recorded HTTP(S) flows attributed to AI agents (newest first), each tagged with the agent, host, method, path, status and how many credential leaks it contained.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/ai/log") })
	s.add("monitor_ai_agents", "Start monitoring all known AI agents: installs a managed intercept rule matching every known agent API host so their HTTPS is transparently MITM'd and passively scanned (catching API keys/passwords they transmit) regardless of which process makes the call, and turns recording + scanning on.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.post("POST", "/api/ai/monitor", nil) })
	s.add("stop_monitoring_ai_agents", "Stop monitoring AI agents: removes the managed AI intercept rule (recording stays as-is).", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.post("DELETE", "/api/ai/monitor", nil) })
	s.add("autostart_status", "Whether the cyberboba daemon is set to start on system boot (systemd 'enabled'), whether it is running now, and which VPNs are flagged to auto-connect when it starts. can_manage=false means boot autostart cannot be toggled here (no systemd or not running as root).", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/system/autostart") })
	s.add("set_autostart", "Enable or disable starting the cyberboba daemon automatically on system boot (systemctl enable/disable). When enabled, on boot the daemon comes up and any VPN with its Autostart flag set auto-connects. Requires the daemon to run as root.",
		schema(map[string]interface{}{"enabled": p("boolean", "true = start on boot, false = do not")}, "enabled"),
		func(a map[string]interface{}) (interface{}, error) {
			b := boolp(a, "enabled")
			if b == nil {
				return nil, fmt.Errorf("enabled is required")
			}
			return s.post("POST", "/api/system/autostart", map[string]interface{}{"enabled": *b})
		})
	s.add("dns_filter_status", "Pi-hole-style DNS filter status: whether blocking is on, how many domains are loaded (from blocklists + manual), total/blocked query counts and percentage, and the top blocked/queried domains.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/dns") })
	s.add("dns_query_log", "Recent DNS queries seen by cyberboba (newest first), each with the name, record type and whether it was blocked. Works as a live DNS monitor even when blocking is off.",
		schema(map[string]interface{}{"limit": p("integer", "max rows (default 200)"), "blocked_only": p("boolean", "only blocked queries")}),
		func(a map[string]interface{}) (interface{}, error) {
			path := "/api/dns/log?limit=" + strconv.Itoa(num(a, "limit"))
			if boolArg(a, "blocked_only") {
				path += "&blocked=1"
			}
			return s.get(path)
		})
	s.add("dns_block", "Block a domain (and its subdomains) at the DNS level for every app; turns the filter on if it was off. Use it to kill an ad/tracker/malware domain in one step.",
		schema(map[string]interface{}{"domain": p("string", "domain to block, e.g. ads.example.com")}, "domain"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/dns/block", map[string]interface{}{"domain": str(a, "domain")})
		})
	s.add("dns_unblock", "Allow a domain again (removes it from the manual block list and whitelists it so list-based blocks no longer catch it).",
		schema(map[string]interface{}{"domain": p("string", "domain to unblock")}, "domain"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/dns/unblock", map[string]interface{}{"domain": str(a, "domain")})
		})
	s.add("dns_refresh_lists", "Re-download the configured DNS blocklists now.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.post("POST", "/api/dns/refresh", nil) })
	s.add("set_dns_filter", "Replace the whole DNS filter config: {enabled, blocklists:[urls], block:[domains], allow:[domains], sinkhole:\"nxdomain\"|\"zero\"}. Read dns_filter_status first and send the full object.",
		schema(map[string]interface{}{"config": map[string]interface{}{"type": "object", "description": "a config.DNSFilter object"}}, "config"),
		func(a map[string]interface{}) (interface{}, error) {
			cfg, ok := a["config"]
			if !ok {
				return nil, fmt.Errorf("config is required")
			}
			return s.post("PUT", "/api/dns", cfg)
		})
	s.add("list_connections", "Live and recent TCP connections with app, destination, matched rule and action (Proxifier view).",
		schema(map[string]interface{}{"limit": p("integer", "max rows (default 100)"), "closed": p("boolean", "include finished connections (default true)")}),
		func(a map[string]interface{}) (interface{}, error) {
			n := num(a, "limit")
			if n == 0 {
				n = 100
			}
			closed := "1"
			if b := boolp(a, "closed"); b != nil && !*b {
				closed = "0"
			}
			return s.get("/api/connections?limit=" + strconv.Itoa(n) + "&closed=" + closed)
		})

	// --- rules ---
	ruleProps := map[string]interface{}{
		"name":      p("string", "unique rule name"),
		"apps":      parr("process names, absolute paths, globs, 'tag:NAME' or 'cmd:SUBSTR'; empty = any app"),
		"users":     parr("user names or uids"),
		"targets":   parr("hostnames, '*.domain', IPs, CIDRs or 'lan'; empty = any"),
		"ports":     parr("ports or ranges like '443', '8000-8100'"),
		"protocols": parr("tcp and/or udp"),
		"action":    p("string", "direct | proxy | vpn | intercept | block"),
		"proxy":     p("string", "proxy name when action=proxy"),
		"vpn":       p("string", "vpn profile name when action=vpn"),
		"enabled":   p("boolean", "default true"),
		"comment":   p("string", ""),
	}
	s.add("list_rules", "Ordered routing rules (first match wins).", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/rules") })
	s.add("set_rules", "Replace the whole ordered rule list.",
		schema(map[string]interface{}{"rules": map[string]interface{}{"type": "array", "items": schema(ruleProps, "name", "action")}}, "rules"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("PUT", "/api/rules", map[string]interface{}{"rules": a["rules"]})
		})
	addRuleProps := map[string]interface{}{}
	for k, v := range ruleProps {
		addRuleProps[k] = v
	}
	addRuleProps["position"] = p("integer", "insert index (0 = top). Default: before the last rule (the catch-all).")
	s.add("add_rule", "Insert one rule. By default it is placed just above the last (catch-all) rule.", schema(addRuleProps, "name", "action"),
		func(a map[string]interface{}) (interface{}, error) {
			var cur struct {
				Rules []map[string]interface{} `json:"rules"`
			}
			if err := s.c.JSON("GET", "/api/rules", nil, &cur); err != nil {
				return nil, err
			}
			r := map[string]interface{}{}
			for k := range ruleProps {
				if v, ok := a[k]; ok {
					r[k] = v
				}
			}
			for _, k := range []string{"apps", "users", "targets", "ports", "protocols"} {
				if l := list(a, k); l != nil {
					r[k] = l
				}
			}
			pos := len(cur.Rules) - 1
			if v, ok := a["position"]; ok && v != nil {
				pos = num(a, "position")
			}
			if pos < 0 {
				pos = 0
			}
			if pos > len(cur.Rules) {
				pos = len(cur.Rules)
			}
			rules := append([]map[string]interface{}{}, cur.Rules[:pos]...)
			rules = append(rules, r)
			rules = append(rules, cur.Rules[pos:]...)
			return s.post("PUT", "/api/rules", map[string]interface{}{"rules": rules})
		})
	s.add("delete_rule", "Delete a rule by name.", schema(map[string]interface{}{"name": p("string", "")}, "name"),
		func(a map[string]interface{}) (interface{}, error) {
			var cur struct {
				Rules []map[string]interface{} `json:"rules"`
			}
			if err := s.c.JSON("GET", "/api/rules", nil, &cur); err != nil {
				return nil, err
			}
			var out []map[string]interface{}
			found := false
			for _, r := range cur.Rules {
				if r["name"] == str(a, "name") {
					found = true
					continue
				}
				out = append(out, r)
			}
			if !found {
				return nil, fmt.Errorf("rule %q not found", str(a, "name"))
			}
			if out == nil {
				out = []map[string]interface{}{}
			}
			return s.post("PUT", "/api/rules", map[string]interface{}{"rules": out})
		})
	s.add("test_rule", "Show which rule would match a connection.",
		schema(map[string]interface{}{"app": p("string", "process name"), "host": p("string", "destination hostname"),
			"ip": p("string", "destination IP"), "port": p("integer", "destination port"), "user": p("string", "")}),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/rules/test", map[string]interface{}{"app": str(a, "app"), "host": str(a, "host"),
				"ip": str(a, "ip"), "port": num(a, "port"), "user": str(a, "user")})
		})

	// --- proxies ---
	proxyProps := map[string]interface{}{
		"name": p("string", ""), "type": p("string", "socks5 | socks4 | http | chain | failover | balance"),
		"addr": p("string", "host:port for socks5/socks4/http"), "username": p("string", ""), "password": p("string", ""),
		"hops": parr("member proxy names for chain/failover/balance"), "via_vpn": p("string", "reach the proxy through this VPN"),
		"remote_dns": p("boolean", "let the proxy resolve hostnames"), "comment": p("string", ""),
	}
	s.add("list_proxies", "Configured upstream proxies and groups.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/proxies") })
	s.add("set_proxies", "Replace the proxy list.", schema(map[string]interface{}{"proxies": map[string]interface{}{"type": "array", "items": schema(proxyProps, "name", "type")}}, "proxies"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("PUT", "/api/proxies", map[string]interface{}{"proxies": a["proxies"]})
		})
	s.add("add_proxy", "Add or replace one proxy by name.", schema(proxyProps, "name", "type"),
		func(a map[string]interface{}) (interface{}, error) {
			var cur struct {
				Proxies []map[string]interface{} `json:"proxies"`
			}
			if err := s.c.JSON("GET", "/api/proxies", nil, &cur); err != nil {
				return nil, err
			}
			np := map[string]interface{}{}
			for k := range proxyProps {
				if v, ok := a[k]; ok {
					np[k] = v
				}
			}
			if l := list(a, "hops"); l != nil {
				np["hops"] = l
			}
			var out []map[string]interface{}
			for _, x := range cur.Proxies {
				if x["name"] != np["name"] {
					out = append(out, x)
				}
			}
			out = append(out, np)
			return s.post("PUT", "/api/proxies", map[string]interface{}{"proxies": out})
		})
	s.add("delete_proxy", "Delete a proxy by name.", schema(map[string]interface{}{"name": p("string", "")}, "name"),
		func(a map[string]interface{}) (interface{}, error) {
			var cur struct {
				Proxies []map[string]interface{} `json:"proxies"`
			}
			if err := s.c.JSON("GET", "/api/proxies", nil, &cur); err != nil {
				return nil, err
			}
			out := []map[string]interface{}{}
			for _, x := range cur.Proxies {
				if x["name"] != str(a, "name") {
					out = append(out, x)
				}
			}
			return s.post("PUT", "/api/proxies", map[string]interface{}{"proxies": out})
		})
	s.add("check_proxy", "Test a proxy by fetching a URL through it; returns latency and exit IP.",
		schema(map[string]interface{}{"name": p("string", ""), "url": p("string", "default https://api.ipify.org")}, "name"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/proxies/"+url.PathEscape(str(a, "name"))+"/check", map[string]string{"url": str(a, "url")})
		})

	// --- vpn ---
	s.add("list_vpns", "VPN profiles with live state (interface, endpoint, bytes, handshake, kill switch).", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/vpn") })
	s.add("vpn_up", "Bring a VPN profile up.", schema(map[string]interface{}{"name": p("string", "")}, "name"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/vpn/"+url.PathEscape(str(a, "name"))+"/up", nil)
		})
	s.add("vpn_down", "Bring a VPN profile down.", schema(map[string]interface{}{"name": p("string", "")}, "name"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/vpn/"+url.PathEscape(str(a, "name"))+"/down", nil)
		})
	s.add("vpn_log", "Backend (wg-quick/openvpn) output for a profile.", schema(map[string]interface{}{"name": p("string", "")}, "name"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.get("/api/vpn/" + url.PathEscape(str(a, "name")) + "/log")
		})
	s.add("vpn_import", "Import a WireGuard (.conf) or OpenVPN (.ovpn) configuration text as a profile.",
		schema(map[string]interface{}{"name": p("string", ""), "content": p("string", "config file text"),
			"type": p("string", "wireguard | openvpn (auto-detected when empty)"), "mode": p("string", "selective (default) | full")}, "name", "content"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/vpn/import", map[string]string{"name": str(a, "name"), "content": str(a, "content"), "type": str(a, "type"), "mode": str(a, "mode")})
		})
	s.add("set_vpns", "Replace the VPN profile list (fields: name,type,config,mode,autostart,auth_file,username,password,kill_switch,reconnect,interface,extra_args).",
		schema(map[string]interface{}{"vpns": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "object"}}}, "vpns"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("PUT", "/api/vpn", map[string]interface{}{"vpns": a["vpns"]})
		})

	// --- intercept ---
	s.add("intercept_status", "Intercepting proxy status: listener, recording/hold switches, flow counts, CA info, scope.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/intercept") })
	s.add("intercept_toggle", "Switch recording / hold_requests / hold_responses at runtime.",
		schema(map[string]interface{}{"recording": p("boolean", ""), "scan": p("boolean", "passive security scanner on/off"), "hold_requests": p("boolean", ""), "hold_responses": p("boolean", "")}),
		func(a map[string]interface{}) (interface{}, error) {
			body := map[string]interface{}{}
			for _, k := range []string{"recording", "scan", "hold_requests", "hold_responses"} {
				if b := boolp(a, k); b != nil {
					body[k] = *b
				}
			}
			return s.post("POST", "/api/intercept/toggle", body)
		})
	s.add("intercept_findings", "Passive security-scan findings across all recorded flows (Caido/Burp-style): leaked secrets/tokens, credentials over plain HTTP, insecure cookies (no Secure/HttpOnly/SameSite), missing security headers (CSP/HSTS/nosniff/X-Frame-Options), permissive CORS, tech/version disclosure and mixed content — grouped by rule with counts, affected flow ids and severity totals.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/intercept/findings") })
	s.add("record_app", "Record one application's traffic (and only that app): installs a managed rule that routes just this program's HTTP/HTTPS through the interceptor and turns recording on — e.g. capture only Chromium or only Claude instead of everything. The app is a process name, absolute path, glob or tag, matching the same syntax as a rule's apps. Needs the CA trusted for HTTPS.",
		schema(map[string]interface{}{"app": p("string", "process name / path / glob / tag to record, e.g. \"chromium\" or \"claude\"")}, "app"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/intercept/record", map[string]interface{}{"app": str(a, "app")})
		})
	s.add("stop_recording_app", "Stop recording an app added with record_app: removes its managed intercept rule. Other apps keep recording.",
		schema(map[string]interface{}{"app": p("string", "the app to stop recording")}, "app"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("DELETE", "/api/intercept/record?app="+url.QueryEscape(str(a, "app")), nil)
		})
	s.add("recorded_apps", "List the applications currently being recorded (added with record_app) and whether recording is on.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/intercept/record") })
	s.add("intercept_configure", "Update intercept settings (scope, passthrough, upstream route, hold defaults, limits). Only given fields change.",
		schema(map[string]interface{}{"scope_include": parr("host patterns in scope"), "scope_exclude": parr("host patterns out of scope"),
			"passthrough": parr("hosts tunneled without TLS termination"), "upstream_action": p("string", "direct | proxy | vpn"),
			"upstream_proxy": p("string", ""), "upstream_vpn": p("string", ""), "hold_requests": p("boolean", ""), "hold_responses": p("boolean", ""),
			"record_only_scope": p("boolean", ""), "verify_upstream_tls": p("boolean", ""), "max_flows": p("integer", ""), "max_body": p("integer", "bytes kept per body")}),
		func(a map[string]interface{}) (interface{}, error) {
			var cur struct {
				Config map[string]interface{} `json:"config"`
			}
			if err := s.c.JSON("GET", "/api/intercept", nil, &cur); err != nil {
				return nil, err
			}
			c := cur.Config
			scope, _ := c["scope"].(map[string]interface{})
			if scope == nil {
				scope = map[string]interface{}{}
			}
			if l := list(a, "scope_include"); l != nil {
				scope["include"] = l
			}
			if l := list(a, "scope_exclude"); l != nil {
				scope["exclude"] = l
			}
			c["scope"] = scope
			if l := list(a, "passthrough"); l != nil {
				c["passthrough"] = l
			}
			up, _ := c["upstream"].(map[string]interface{})
			if up == nil {
				up = map[string]interface{}{"action": "direct"}
			}
			if v := str(a, "upstream_action"); v != "" {
				up["action"] = v
			}
			if v, ok := a["upstream_proxy"]; ok {
				up["proxy"] = v
			}
			if v, ok := a["upstream_vpn"]; ok {
				up["vpn"] = v
			}
			c["upstream"] = up
			for _, k := range []string{"hold_requests", "hold_responses", "record_only_scope", "verify_upstream_tls"} {
				if b := boolp(a, k); b != nil {
					c[k] = *b
				}
			}
			for _, k := range []string{"max_flows", "max_body"} {
				if n := num(a, k); n > 0 {
					c[k] = n
				}
			}
			return s.post("PUT", "/api/intercept", c)
		})
	s.add("list_flows", "Captured HTTP flows (newest first), without bodies. Filter by substring, host, method, status prefix, scope.",
		schema(map[string]interface{}{"q": p("string", "substring of URL/app/content-type"), "host": p("string", ""), "method": p("string", ""),
			"status": p("string", "exact or prefix, e.g. 200 or 4"), "scope_only": p("boolean", ""), "source": p("string", "transparent | proxy | repeater"),
			"limit": p("integer", "default 50"), "offset": p("integer", "")}),
		func(a map[string]interface{}) (interface{}, error) {
			q := url.Values{}
			for _, k := range []string{"q", "host", "method", "status", "source"} {
				if v := str(a, k); v != "" {
					q.Set(k, v)
				}
			}
			if b := boolp(a, "scope_only"); b != nil && *b {
				q.Set("scope", "1")
			}
			n := num(a, "limit")
			if n == 0 {
				n = 50
			}
			q.Set("limit", strconv.Itoa(n))
			if o := num(a, "offset"); o > 0 {
				q.Set("offset", strconv.Itoa(o))
			}
			return s.get("/api/intercept/flows?" + q.Encode())
		})
	s.add("get_flow", "One flow with request/response bodies and raw HTTP text.", schema(map[string]interface{}{"id": p("integer", "")}, "id"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.get("/api/intercept/flows/" + strconv.Itoa(num(a, "id")))
		})
	s.add("flow_as_curl", "Render a captured flow as a curl command.", schema(map[string]interface{}{"id": p("integer", "")}, "id"),
		func(a map[string]interface{}) (interface{}, error) {
			b, err := s.c.Do("GET", "/api/intercept/flows/"+strconv.Itoa(num(a, "id"))+"/export?format=curl", nil)
			return string(b), err
		})
	s.add("delete_flows", "Delete one flow (id) or all flows.", schema(map[string]interface{}{"id": p("integer", "omit to clear everything")}),
		func(a map[string]interface{}) (interface{}, error) {
			if n := num(a, "id"); n > 0 {
				return s.post("DELETE", "/api/intercept/flows/"+strconv.Itoa(n), nil)
			}
			return s.post("DELETE", "/api/intercept/flows", nil)
		})
	s.add("export_har", "Export captured flows as a HAR document (JSON text).", schema(map[string]interface{}{"q": p("string", ""), "host": p("string", ""), "scope_only": p("boolean", "")}),
		func(a map[string]interface{}) (interface{}, error) {
			q := url.Values{}
			if v := str(a, "q"); v != "" {
				q.Set("q", v)
			}
			if v := str(a, "host"); v != "" {
				q.Set("host", v)
			}
			if b := boolp(a, "scope_only"); b != nil && *b {
				q.Set("scope", "1")
			}
			b, err := s.c.Do("GET", "/api/intercept/export?"+q.Encode(), nil)
			return string(b), err
		})
	s.add("pending_flows", "Flows currently held by the interceptor (with raw request/response text).", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/intercept/pending") })
	s.add("forward_flow", "Release a held flow, optionally replacing the raw request (pending_request) or response (pending_response).",
		schema(map[string]interface{}{"id": p("integer", ""), "raw": p("string", "edited raw HTTP message; omit to forward unchanged")}, "id"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/intercept/pending/"+strconv.Itoa(num(a, "id"))+"/forward", map[string]string{"raw": str(a, "raw")})
		})
	s.add("drop_flow", "Drop a held flow (client gets 502).", schema(map[string]interface{}{"id": p("integer", "")}, "id"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/intercept/pending/"+strconv.Itoa(num(a, "id"))+"/drop", nil)
		})
	s.add("forward_all", "Release every held flow unchanged.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/intercept/pending/forward-all", nil)
		})
	s.add("send_request", "Repeater: send a raw HTTP/1.1 request to host:port (TLS optional) through the intercept upstream route and return the full flow with response.",
		schema(map[string]interface{}{"host": p("string", "target host (default: Host header)"), "port": p("integer", "default 443 for tls, 80 otherwise"),
			"tls": p("boolean", "use HTTPS"), "raw": p("string", "raw request text, e.g. 'GET /path HTTP/1.1\\nHost: example.com\\n\\n'"),
			"follow_redirects": p("boolean", ""), "timeout_sec": p("integer", "default 30")}, "raw"),
		func(a map[string]interface{}) (interface{}, error) {
			body := map[string]interface{}{"host": str(a, "host"), "port": num(a, "port"), "raw": str(a, "raw"), "timeout_sec": num(a, "timeout_sec")}
			if b := boolp(a, "tls"); b != nil {
				body["tls"] = *b
			}
			if b := boolp(a, "follow_redirects"); b != nil {
				body["follow_redirects"] = *b
			}
			return s.post("POST", "/api/intercept/send", body)
		})
	s.add("ca_cert", "The intercept CA certificate (PEM) clients must trust for HTTPS interception.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) {
			b, err := s.c.Do("GET", "/api/intercept/ca", nil)
			return string(b), err
		})
	s.add("install_ca", "Install the intercept CA into the system trust store and browser NSS databases.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/intercept/ca/install", nil)
		})

	// --- v0.3 tools ---
	s.add("list_flows_by_body", "Search captured flows by a substring inside request/response bodies.",
		schema(map[string]interface{}{"body": p("string", "substring to find in bodies"), "host": p("string", ""), "limit": p("integer", "default 50")}, "body"),
		func(a map[string]interface{}) (interface{}, error) {
			q := url.Values{}
			q.Set("body", str(a, "body"))
			if v := str(a, "host"); v != "" {
				q.Set("host", v)
			}
			n := num(a, "limit")
			if n == 0 {
				n = 50
			}
			q.Set("limit", strconv.Itoa(n))
			return s.get("/api/intercept/flows?" + q.Encode())
		})
	s.add("wait_for_flow", "Block until a captured flow matches (host/method/status/body substring) or timeout. Returns the first match.",
		schema(map[string]interface{}{"host": p("string", ""), "method": p("string", ""), "status": p("string", "exact or prefix"),
			"body": p("string", "substring in bodies"), "q": p("string", "substring in URL"), "timeout_sec": p("integer", "default 30"),
			"since_id": p("integer", "only flows with id greater than this")}),
		func(a map[string]interface{}) (interface{}, error) {
			timeout := num(a, "timeout_sec")
			if timeout == 0 {
				timeout = 30
			}
			since := num(a, "since_id")
			q := url.Values{}
			for _, k := range []string{"host", "method", "status", "body", "q"} {
				if v := str(a, k); v != "" {
					q.Set(k, v)
				}
			}
			q.Set("limit", "200")
			deadline := time.Now().Add(time.Duration(timeout) * time.Second)
			for time.Now().Before(deadline) {
				var res struct {
					Flows []map[string]interface{} `json:"flows"`
				}
				if err := s.c.JSON("GET", "/api/intercept/flows?"+q.Encode(), nil, &res); err != nil {
					return nil, err
				}
				// flows come newest-first; find the oldest matching one above since_id
				var match map[string]interface{}
				for i := len(res.Flows) - 1; i >= 0; i-- {
					if id, _ := res.Flows[i]["id"].(float64); int(id) > since {
						match = res.Flows[i]
						break
					}
				}
				if match != nil {
					return match, nil
				}
				time.Sleep(500 * time.Millisecond)
			}
			return "timeout: no matching flow", nil
		})
	rwProps := map[string]interface{}{
		"name": p("string", ""), "enabled": p("boolean", "default true"),
		"target": p("string", "request | response"), "part": p("string", "header | body | url"),
		"header": p("string", "header name when part=header"), "match": p("string", "regex; empty + header sets the header to replace"),
		"replace": p("string", "replacement, supports $1 groups"), "remove": p("boolean", "delete header / matched text"),
		"hosts": parr("optional host patterns to scope the rewrite"),
	}
	s.add("list_rewrites", "List match & replace rules applied to intercepted flows.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/intercept/rewrites") })
	s.add("set_rewrites", "Replace all match & replace rules.",
		schema(map[string]interface{}{"rewrites": map[string]interface{}{"type": "array", "items": schema(rwProps, "target", "part")}}, "rewrites"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("PUT", "/api/intercept/rewrites", map[string]interface{}{"rewrites": a["rewrites"]})
		})
	s.add("add_rewrite", "Add one match & replace rule (e.g. inject a header, strip CSP, patch a response body).", schema(rwProps, "target", "part"),
		func(a map[string]interface{}) (interface{}, error) {
			var cur struct {
				Rewrites []map[string]interface{} `json:"rewrites"`
			}
			if err := s.c.JSON("GET", "/api/intercept/rewrites", nil, &cur); err != nil {
				return nil, err
			}
			nw := map[string]interface{}{}
			for k := range rwProps {
				if v, ok := a[k]; ok {
					nw[k] = v
				}
			}
			if l := list(a, "hosts"); l != nil {
				nw["hosts"] = l
			}
			cur.Rewrites = append(cur.Rewrites, nw)
			return s.post("PUT", "/api/intercept/rewrites", map[string]interface{}{"rewrites": cur.Rewrites})
		})
	s.add("save_session", "Save all captured flows (with bodies) to a session file on the daemon host.",
		schema(map[string]interface{}{"path": p("string", "optional; default timestamped file in the session dir")}),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/intercept/session/save", map[string]string{"path": str(a, "path")})
		})
	s.add("load_session", "Load flows from a saved session file.",
		schema(map[string]interface{}{"path": p("string", ""), "replace": p("boolean", "clear current flows first")}, "path"),
		func(a map[string]interface{}) (interface{}, error) {
			body := map[string]interface{}{"path": str(a, "path")}
			if b := boolp(a, "replace"); b != nil {
				body["replace"] = *b
			}
			return s.post("POST", "/api/intercept/session/load", body)
		})
	s.add("list_sessions", "List saved intercept session files.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/intercept/sessions") })
	s.add("firewall_status", "ZoneAlarm-style application firewall status: mode, stealth, internet lock, trusted zones, program count, pending prompts and allow/block/ask counters.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/firewall") })
	s.add("firewall_activity", "Recent firewall decisions (newest first): what the firewall blocked, prompted on, or auto-learned, each with app, destination, zone, allow/deny and reason. Use this to answer \"what did the firewall block?\" — e.g. when a program could not reach the network. blocked:true shows only blocks.",
		schema(map[string]interface{}{"limit": p("integer", "max rows (default 200)"), "blocked": p("boolean", "only blocked decisions")}),
		func(a map[string]interface{}) (interface{}, error) {
			path := "/api/firewall/activity?limit=" + strconv.Itoa(num(a, "limit"))
			if boolArg(a, "blocked") {
				path += "&blocked=1"
			}
			return s.get(path)
		})
	s.add("firewall_pending", "List held connections awaiting a firewall decision (the ZoneAlarm-style prompts).", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/firewall/pending") })
	s.add("firewall_answer", "Allow or deny a held connection by id; optionally remember the decision for that program/zone.",
		schema(map[string]interface{}{"id": p("integer", "pending ask id"), "allow": p("boolean", "true=allow, false=deny"), "remember": p("boolean", "persist a program rule for this app+zone")}, "id", "allow"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/firewall/answer", map[string]interface{}{"id": num(a, "id"), "allow": boolArg(a, "allow"), "remember": boolArg(a, "remember")})
		})
	s.add("firewall_answer_all", "Resolve every pending firewall prompt at once (allow or deny all).",
		schema(map[string]interface{}{"allow": p("boolean", "true=allow all, false=deny all")}, "allow"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/firewall/answer_all", map[string]interface{}{"allow": boolArg(a, "allow")})
		})
	s.add("firewall_set_mode", "Set program-control mode: off (allow all), ask (prompt unknown apps), auto (allow & remember), block (deny unknown).",
		schema(map[string]interface{}{"mode": p("string", "off|ask|auto|block")}, "mode"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/firewall/mode", map[string]interface{}{"mode": str(a, "mode")})
		})
	s.add("firewall_lock", "Internet Lock panic switch: block all traffic except programs marked lock_pass.",
		schema(map[string]interface{}{"on": p("boolean", "true=lock, false=unlock")}, "on"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/firewall/lock", map[string]interface{}{"on": boolArg(a, "on")})
		})
	s.add("firewall_stealth", "Inbound stealth: silently drop unsolicited inbound packets so ports are invisible to scans (needs root).",
		schema(map[string]interface{}{"on": p("boolean", "true=stealth on")}, "on"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/firewall/stealth", map[string]interface{}{"on": boolArg(a, "on")})
		})
	s.add("firewall_block", "Block a destination host, domain (*.example.com), IP or CIDR for every program — the one-click block for a host an app reached on the live map. Enforced even when program control is off.",
		schema(map[string]interface{}{"host": p("string", "hostname, *.domain, glob, IP or CIDR to block")}, "host"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/firewall/block", map[string]interface{}{"host": str(a, "host")})
		})
	s.add("firewall_unblock", "Remove a host/domain/IP/CIDR from the firewall blocklist.",
		schema(map[string]interface{}{"host": p("string", "the exact blocklist entry to remove")}, "host"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("POST", "/api/firewall/unblock", map[string]interface{}{"host": str(a, "host")})
		})
	s.add("set_firewall", "Replace the whole firewall configuration (enabled, mode, stealth, internet_lock, trusted_nets, programs, blocked_hosts). Read firewall_status first and send the full object.",
		schema(map[string]interface{}{"config": map[string]interface{}{"type": "object", "description": "a config.Firewall object"}}, "config"),
		func(a map[string]interface{}) (interface{}, error) {
			cfg, ok := a["config"]
			if !ok {
				return nil, fmt.Errorf("config is required")
			}
			return s.post("PUT", "/api/firewall", cfg)
		})
	s.add("list_installed_apps", "List installed desktop applications (freedesktop .desktop entries) with human-friendly names and a suggested `cmd:` match keyword — useful to route an app by its real name instead of guessing the process name.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/apps/installed") })
	s.add("list_tags", "List tag cgroups (processes started with `cyberboba run -tag`) and their UDP policy.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/tags") })
	s.add("rotation_status", "Live state of proxy rotation groups (type \"rotate\"): current active member, members, interval and seconds until the next switch.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/proxies/rotation") })
	s.add("vpn_rotations", "List VPN rotations (cycle the active tunnel among a set) with their live status.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/vpn/rotations") })
	s.add("set_vpn_rotations", "Replace the VPN rotations. Each: {name, enabled, vpns:[...], every_sec, mode:random|sequential}.",
		schema(map[string]interface{}{"rotations": map[string]interface{}{"type": "array", "description": "array of VPN rotation objects"}}, "rotations"),
		func(a map[string]interface{}) (interface{}, error) {
			return s.post("PUT", "/api/vpn/rotations", map[string]interface{}{"rotations": a["rotations"]})
		})
	s.add("traffic_graph", "Traffic topology for the live map: nodes (this machine, VPNs, proxies, destinations with country), edges, per-rule paths, and current connections each annotated with the ordered chain of hops and the destination country. Use it to see how traffic actually flows through chained VPNs/proxies and where it exits.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/topology") })
	s.add("traffic_map", "Live geographic map data: this machine's own location (home) plus every current destination aggregated into a point with latitude/longitude, country, city, ISP, the apps connecting to it, byte counts and whether it is already blocked. Use it to see geographically where each application is connecting.", schema(nil),
		func(a map[string]interface{}) (interface{}, error) { return s.get("/api/map") })
	s.add("geo_lookup", "Resolve an IP address or hostname to a country, city and ISP (cached).", schema(map[string]interface{}{"ip": p("string", "IP address or hostname")}, "ip"),
		func(a map[string]interface{}) (interface{}, error) {
			ip := str(a, "ip")
			if ip == "" {
				return nil, fmt.Errorf("ip is required")
			}
			return s.get("/api/geo/" + url.PathEscape(ip))
		})
	s.add("test_route_live", "Live end-to-end route test: evaluate the rules for an (app, host, port), actually dial a URL through the resolved route (proxy/VPN/chain), and report the real exit IP, its country and latency. Proves a route works and where it exits.",
		schema(map[string]interface{}{
			"host": p("string", "destination host (e.g. api.example.com)"),
			"app":  p("string", "process name to attribute the connection to (optional)"),
			"port": p("integer", "destination port (default 443)"),
			"url":  p("string", "URL to fetch through the route (default https://api.ipify.org)"),
		}, "host"),
		func(a map[string]interface{}) (interface{}, error) {
			body := map[string]interface{}{"host": str(a, "host"), "app": str(a, "app"), "url": str(a, "url")}
			if n := num(a, "port"); n > 0 {
				body["port"] = n
			}
			return s.post("POST", "/api/route/test", body)
		})
	s.add("probe_route", "Live-test an UNSAVED hop chain: dial a URL through [optional one VPN] + proxies (in order) without changing config, and report the real exit IP, country and latency. Use it to try a chain before creating a rule.",
		schema(map[string]interface{}{
			"vpn":     p("string", "a VPN profile to go through first (optional; at most one)"),
			"proxies": parr("proxy names to chain, in order (optional)"),
			"url":     p("string", "URL to fetch (default https://api.ipify.org)"),
		}),
		func(a map[string]interface{}) (interface{}, error) {
			hops := []map[string]string{}
			if v := str(a, "vpn"); v != "" {
				hops = append(hops, map[string]string{"kind": "vpn", "name": v})
			}
			for _, pn := range list(a, "proxies") {
				hops = append(hops, map[string]string{"kind": "proxy", "name": pn})
			}
			if len(hops) == 0 {
				return nil, fmt.Errorf("provide a vpn and/or proxies")
			}
			return s.post("POST", "/api/route/probe", map[string]interface{}{"hops": hops, "url": str(a, "url")})
		})
}
