package api

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"cyberboba/internal/aiagents"
	"cyberboba/internal/config"
	"cyberboba/internal/intercept"
)

const aiRecMark = "cyberboba:ai-record"

func (s *Server) aiRoutes() {
	m := s.mux

	// GET /api/ai — the AI-agent control centre snapshot: which known agents
	// are running, what endpoints they contact, their live bandwidth, and any
	// credentials/secrets they were seen sending (the headline security view).
	m.HandleFunc("GET /api/ai", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.aiSnapshot())
	})

	// GET /api/ai/log — recent recorded flows attributed to AI agents, newest
	// first, each tagged with the agent it belongs to.
	m.HandleFunc("GET /api/ai/log", func(w http.ResponseWriter, r *http.Request) {
		out := []map[string]interface{}{}
		if s.d.Icpt != nil {
			flows, _ := s.d.Icpt.Store().List(intercept.Filter{}, 0, 0)
			for i := len(flows) - 1; i >= 0 && len(out) < 300; i-- {
				f := &flows[i]
				ag, ok := attributeFlow(f)
				if !ok {
					continue
				}
				out = append(out, map[string]interface{}{
					"id": f.ID, "agent": ag.Key, "agent_name": ag.Name, "time": f.Time,
					"method": f.Method, "host": f.Host, "path": f.Path, "status": f.Status,
					"app": f.App, "leaks": len(secretFindings(f.Findings))})
			}
		}
		writeJSON(w, map[string]interface{}{"log": out})
	})

	// POST /api/ai/monitor — start monitoring all known agents: install a
	// managed intercept rule matching every known agent API host (so their
	// HTTPS is MITM'd and passively scanned no matter which process makes the
	// call), and turn recording + scanning on.
	m.HandleFunc("POST /api/ai/monitor", func(w http.ResponseWriter, r *http.Request) {
		if s.d.Icpt == nil {
			writeErr(w, 503, errors.New("intercept engine is disabled"))
			return
		}
		var hosts []string
		for _, a := range aiagents.Registry {
			hosts = append(hosts, a.Hosts...)
		}
		sort.Strings(hosts)
		if err := s.d.Store.Mutate(func(c *config.Config) error {
			// drop any existing managed AI rule, then re-insert fresh
			out := c.Rules[:0]
			for _, rl := range c.Rules {
				if rl.Comment != aiRecMark {
					out = append(out, rl)
				}
			}
			c.Rules = out
			t := true
			rule := config.Rule{Name: "Monitor AI agents", Enabled: &t, Comment: aiRecMark,
				Targets: hosts, Action: config.ActionIntercept}
			idx := len(c.Rules)
			for i, rl := range c.Rules {
				if len(rl.Apps) == 0 && len(rl.Targets) == 0 && len(rl.Users) == 0 && len(rl.Ports) == 0 && len(rl.Protocols) == 0 {
					idx = i
					break
				}
			}
			c.Rules = append(c.Rules[:idx:idx], append([]config.Rule{rule}, c.Rules[idx:]...)...)
			return nil
		}); err != nil {
			writeErr(w, 400, err)
			return
		}
		rec, scan := true, true
		s.d.Icpt.Toggle(&rec, &scan, nil, nil)
		writeJSON(w, s.aiSnapshot())
	})

	// DELETE /api/ai/monitor — stop monitoring: remove the managed AI rule.
	m.HandleFunc("DELETE /api/ai/monitor", func(w http.ResponseWriter, r *http.Request) {
		if err := s.d.Store.Mutate(func(c *config.Config) error {
			out := c.Rules[:0]
			for _, rl := range c.Rules {
				if rl.Comment != aiRecMark {
					out = append(out, rl)
				}
			}
			c.Rules = out
			return nil
		}); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, s.aiSnapshot())
	})
}

// secretFindings keeps only the credential-leak findings (API keys, tokens,
// private keys, passwords, cleartext secrets) from a flow's findings.
func secretFindings(fs []intercept.Finding) []intercept.Finding {
	var out []intercept.Finding
	for _, f := range fs {
		if strings.HasPrefix(f.Rule, "secret.") || f.Rule == "transport.cleartext-secret" {
			out = append(out, f)
		}
	}
	return out
}

// attributeFlow maps a recorded flow to a known agent, preferring the
// destination host (reliable) over the owning process name.
func attributeFlow(f *intercept.Flow) (aiagents.Agent, bool) {
	if a, ok := aiagents.MatchHost(f.Host); ok {
		return a, true
	}
	if f.App != "" {
		if a, ok := aiagents.MatchProc(f.App, f.App); ok {
			return a, true
		}
	}
	return aiagents.Agent{}, false
}

func (s *Server) aiSnapshot() map[string]interface{} {
	type endpoint struct {
		Host     string    `json:"host"`
		Requests int       `json:"requests"`
		Bytes    int64     `json:"bytes"`
		Last     time.Time `json:"last"`
	}
	type leak struct {
		Rule     string `json:"rule"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Host     string `json:"host"`
		FlowID   uint64 `json:"flow_id"`
		Where    string `json:"where"`
		Detail   string `json:"detail"`
	}
	type running struct {
		PID   int     `json:"pid"`
		User  string  `json:"user"`
		CPU   float64 `json:"cpu_pct"`
		RSSKB int64   `json:"rss_kb"`
		Cmd   string  `json:"cmd"`
	}
	type agentView struct {
		Key       string                 `json:"key"`
		Name      string                 `json:"name"`
		Vendor    string                 `json:"vendor"`
		Running   []running              `json:"running"`
		LiveConns int                    `json:"live_conns"`
		LiveHosts []string               `json:"live_hosts"`
		Bandwidth map[string]interface{} `json:"bandwidth"`
		Endpoints []endpoint             `json:"endpoints"`
		Flows     int                    `json:"flows"`
		Leaks     []leak                 `json:"leaks"`
		LeakCount int                    `json:"leak_count"`
		Monitored bool                   `json:"monitored"`
	}

	views := map[string]*agentView{}
	get := func(a aiagents.Agent) *agentView {
		v := views[a.Key]
		if v == nil {
			v = &agentView{Key: a.Key, Name: a.Name, Vendor: a.Vendor,
				Running: []running{}, LiveHosts: []string{}, Endpoints: []endpoint{}, Leaks: []leak{}}
			views[a.Key] = v
		}
		return v
	}

	// 1. running processes
	if s.d.ProcMon != nil {
		for _, p := range s.d.ProcMon.List() {
			if p.Kernel {
				continue
			}
			if a, ok := aiagents.MatchProc(p.Name, p.Cmd); ok {
				v := get(a)
				cmd := p.Cmd
				if len(cmd) > 160 {
					cmd = cmd[:160] + "…"
				}
				v.Running = append(v.Running, running{PID: p.PID, User: p.User, CPU: p.CPUPct, RSSKB: p.RSSKB, Cmd: cmd})
			}
		}
	}

	// 2. live connections
	liveHostSet := map[string]map[string]bool{}
	if s.d.Tracker != nil {
		conns := s.d.Tracker.List(0, true)
		for i := range conns {
			c := &conns[i]
			if c.State != "open" {
				continue
			}
			var ag aiagents.Agent
			var ok bool
			if c.Host != "" {
				ag, ok = aiagents.MatchHost(c.Host)
			}
			if !ok && c.App != "" {
				ag, ok = aiagents.MatchProc(c.App, c.App)
			}
			if !ok {
				continue
			}
			v := get(ag)
			v.LiveConns++
			if c.Host != "" {
				if liveHostSet[ag.Key] == nil {
					liveHostSet[ag.Key] = map[string]bool{}
				}
				liveHostSet[ag.Key][c.Host] = true
			}
		}
	}
	for key, hs := range liveHostSet {
		for h := range hs {
			views[key].LiveHosts = append(views[key].LiveHosts, h)
		}
		sort.Strings(views[key].LiveHosts)
	}

	// 3. bandwidth
	if s.d.Bandwidth != nil {
		for _, u := range s.d.Bandwidth.Snapshot().Apps {
			if a, ok := aiagents.MatchProc(u.App, u.App); ok {
				v := get(a)
				v.Bandwidth = map[string]interface{}{
					"rate_in": u.RateIn, "rate_out": u.RateOut,
					"today_in": u.TodayIn, "today_out": u.TodayOut,
					"total_in": u.TotalIn, "total_out": u.TotalOut}
			}
		}
	}

	// 4. recorded flows → endpoints + credential leaks
	totalLeaks, totalFlows := 0, 0
	if s.d.Icpt != nil {
		flows, _ := s.d.Icpt.Store().List(intercept.Filter{}, 0, 0)
		epByAgent := map[string]map[string]*endpoint{}
		for i := range flows {
			f := &flows[i]
			ag, ok := attributeFlow(f)
			if !ok {
				continue
			}
			v := get(ag)
			v.Flows++
			totalFlows++
			if epByAgent[ag.Key] == nil {
				epByAgent[ag.Key] = map[string]*endpoint{}
			}
			ep := epByAgent[ag.Key][f.Host]
			if ep == nil {
				ep = &endpoint{Host: f.Host}
				epByAgent[ag.Key][f.Host] = ep
			}
			ep.Requests++
			ep.Bytes += f.ReqSize + f.RespSize
			if f.Time.After(ep.Last) {
				ep.Last = f.Time
			}
			for _, fd := range secretFindings(f.Findings) {
				v.Leaks = append(v.Leaks, leak{Rule: fd.Rule, Title: fd.Title, Severity: fd.Severity,
					Host: f.Host, FlowID: f.ID, Where: fd.Where, Detail: fd.Detail})
				v.LeakCount++
				totalLeaks++
			}
		}
		for key, eps := range epByAgent {
			v := views[key]
			for _, ep := range eps {
				v.Endpoints = append(v.Endpoints, *ep)
			}
			sort.Slice(v.Endpoints, func(i, j int) bool { return v.Endpoints[i].Requests > v.Endpoints[j].Requests })
		}
	}

	// monitoring status
	monitoring := false
	for _, rl := range s.d.Store.Get().Rules {
		if rl.Comment == aiRecMark {
			monitoring = true
			break
		}
	}
	recording := s.d.Icpt != nil && s.d.Icpt.Status().Recording
	for _, v := range views {
		v.Monitored = monitoring
	}

	// assemble: active agents (running or seen) sorted leaks→running→flows,
	// plus the list of idle known agents for completeness.
	active := []*agentView{}
	activeKeys := map[string]bool{}
	for _, v := range views {
		active = append(active, v)
		activeKeys[v.Key] = true
	}
	sort.Slice(active, func(i, j int) bool {
		if active[i].LeakCount != active[j].LeakCount {
			return active[i].LeakCount > active[j].LeakCount
		}
		if len(active[i].Running) != len(active[j].Running) {
			return len(active[i].Running) > len(active[j].Running)
		}
		if active[i].Flows != active[j].Flows {
			return active[i].Flows > active[j].Flows
		}
		return active[i].Name < active[j].Name
	})
	idle := []map[string]string{}
	for _, a := range aiagents.Registry {
		if !activeKeys[a.Key] {
			idle = append(idle, map[string]string{"key": a.Key, "name": a.Name, "vendor": a.Vendor})
		}
	}

	runningCount := 0
	for _, v := range active {
		if len(v.Running) > 0 {
			runningCount++
		}
	}
	return map[string]interface{}{
		"agents":     active,
		"idle":       idle,
		"monitoring": monitoring,
		"recording":  recording,
		"enabled":    s.d.Icpt != nil,
		"summary": map[string]interface{}{
			"agents_active":  len(active),
			"agents_running": runningCount,
			"known":          len(aiagents.Registry),
			"total_leaks":    totalLeaks,
			"total_flows":    totalFlows,
		},
	}
}
