// cyberboba is the command line client for cyberbobad.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	apiclient "cyberboba/internal/client"
	"cyberboba/internal/mcp"
)

var (
	sock   = flag.String("socket", "/run/cyberboba/cyberboba.sock", "daemon unix socket")
	api    = flag.String("api", "", "daemon TCP address instead of the socket (e.g. 127.0.0.1:7471)")
	token  = flag.String("token", os.Getenv("CYBERBOBA_TOKEN"), "api token")
	asJSON = flag.Bool("json", false, "print raw JSON")
)

func usage() {
	fmt.Fprint(os.Stderr, `CyberBoba Security Suite - proxifier + VPN manager + Caido control (cli: cyberboba)

usage: cyberboba [flags] <command> [args]

  status                          daemon status
  proxify on|off                  enable/disable transparent interception
  conns [-closed] [-follow]       live connection list (Proxifier view)
  rules                           list rules
  rules test <app> <host[:port]>  show which rule matches
  proxies                         list proxies
  proxies check <name> [url]      test a proxy
  vpn                             list VPN profiles
  vpn up|down|log <name>
  vpn import <name> <file> [-type wireguard|openvpn] [-mode full|selective]
  caido                           Caido status
  caido start|stop|restart|install|log
  caido ca-install [ca.crt]       trust Caido's CA system-wide and in browsers
  config                          print configuration (YAML)
  config apply <file.yaml>        replace configuration
  run [-tag NAME] -- cmd args...  run a program tagged for rules ("tag:NAME")
  log [-follow]                   daemon log
  doctor                          environment checks
  intercept                       intercept status
  intercept on|off|hold-req on|off|hold-resp on|off
  intercept flows [-q s] [-host h] [-status 4] [-limit n]
  intercept flow <id> [-raw]      full flow with bodies
  intercept pending | forward <id> [file] | drop <id> | forward-all
  intercept send -host h [-port p] [-tls] [-follow] <rawfile|->   repeater
  intercept ca [install|path]     CA certificate
  intercept export [-o file.har]  HAR export
  topology                        traffic map: hops per rule + live flows (--json)
  geo <ip|host>                   geolocate an address (country/city/ISP)
  apps                            list installed desktop applications
  firewall [mode|lock|stealth|pending|allow|deny|block|unblock]  ZoneAlarm-style app firewall
  ps [--all]                       process viewer (CPU/mem/owner; --all incl. system)
  kill <pid> [KILL]                send SIGTERM (or SIGKILL) to a process
  sysstat                          CPU / memory load and temperatures
  reclaim [--swap] [--all]         free memory: drop caches (+ swap/compact)
  bandwidth                        per-app bandwidth: live speed + data usage
  dns [log|block|unblock|refresh]  DNS ad/tracker blocklist + query log
  route-test <host>               live test: dial through the matched route, show exit IP
  mcp                             run the MCP server (stdio) for AI agents
  api <METHOD> <path> [json]      raw API call (prints JSON)

flags:
`)
	flag.PrintDefaults()
}

func client() *http.Client {
	if *api != "" {
		return &http.Client{Timeout: 5 * time.Minute}
	}
	return &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", *sock)
		}}}
}

func call(method, path string, body interface{}) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = strings.NewReader(s)
		} else {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
	}
	base := "http://cyberboba"
	if *api != "" {
		base = "http://" + *api
	}
	req, _ := http.NewRequest(method, base+path, rd)
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach daemon: %v (is cyberbobad running?)", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var e struct{ Error string }
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return nil, fmt.Errorf("%s", e.Error)
	}
	return data, nil
}

func must(data json.RawMessage, err error) json.RawMessage {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	return data
}

func printJSON(data json.RawMessage) {
	var buf bytes.Buffer
	_ = json.Indent(&buf, data, "", "  ")
	fmt.Println(buf.String())
}

func decode(data json.RawMessage, v interface{}) {
	if err := json.Unmarshal(data, v); err != nil {
		fmt.Fprintln(os.Stderr, "bad response:", err)
		os.Exit(1)
	}
}

func fmtBytes(n float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", n, units[i])
}

func main() {
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "status":
		cmdStatus()
	case "proxify":
		if len(rest) != 1 || (rest[0] != "on" && rest[0] != "off") {
			fatal("usage: cyberboba proxify on|off")
		}
		verb := "enable"
		if rest[0] == "off" {
			verb = "disable"
		}
		must(call("POST", "/api/proxify/"+verb, nil))
		fmt.Println("proxify", rest[0])
	case "conns", "connections":
		cmdConns(rest)
	case "rules":
		cmdRules(rest)
	case "proxies":
		cmdProxies(rest)
	case "vpn":
		cmdVPN(rest)
	case "caido":
		cmdCaido(rest)
	case "config":
		cmdConfig(rest)
	case "run":
		cmdRun(rest)
	case "log":
		cmdLog(rest)
	case "intercept":
		cmdIntercept(rest)
	case "topology", "topo", "map":
		cmdTopology(rest)
	case "geo":
		cmdGeo(rest)
	case "apps":
		cmdApps(rest)
	case "ps", "procmon", "processes":
		cmdProcmon(rest)
	case "kill":
		cmdKill(rest)
	case "sysstat", "sys":
		cmdSysstat(rest)
	case "reclaim", "freemem":
		cmdReclaim(rest)
	case "bandwidth", "bw", "net":
		cmdBandwidth(rest)
	case "dns":
		cmdDNS(rest)
	case "ai", "agents":
		cmdAI(rest)
	case "autostart", "boot":
		cmdAutostart(rest)
	case "firewall", "fw":
		cmdFirewall(rest)
	case "route-test", "probe":
		cmdRouteTest(rest)
	case "mcp":
		srv := mcp.New(apiclient.New(*sock, *api, *token))
		if err := srv.Serve(os.Stdin); err != nil {
			fatal(err.Error())
		}
	case "api":
		if len(rest) < 2 {
			fatal("usage: cyberboba api METHOD /api/path [json-body]")
		}
		var body interface{}
		if len(rest) > 2 {
			body = rest[2]
		}
		data := must(call(strings.ToUpper(rest[0]), rest[1], body))
		if json.Valid(data) {
			printJSON(data)
		} else {
			os.Stdout.Write(data)
		}
	case "doctor":
		var v struct {
			Checks []struct {
				Name   string
				OK     bool
				Detail string
			}
		}
		data := must(call("GET", "/api/doctor", nil))
		if *asJSON {
			printJSON(data)
			return
		}
		decode(data, &v)
		for _, c := range v.Checks {
			mark := "ok  "
			if !c.OK {
				mark = "FAIL"
			}
			fmt.Printf("[%s] %-22s %s\n", mark, c.Name, c.Detail)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func cmdTopology(rest []string) {
	data := must(call("GET", "/api/topology", nil))
	if *asJSON {
		printJSON(data)
		return
	}
	var g struct {
		GeoEnabled bool `json:"geo_enabled"`
		Nodes      []struct {
			ID, Kind, Label, State, Type, Country, City, Flag string
		} `json:"nodes"`
		Paths []struct {
			Rule, Action, Match string
			Nodes               []string
			Enabled             bool
		} `json:"paths"`
		Live []struct {
			App, Host, Action, Country, Flag string
			Nodes                            []string
		} `json:"live"`
	}
	decode(data, &g)
	label := map[string]string{}
	for _, n := range g.Nodes {
		l := n.Label
		if n.Flag != "" {
			l += " " + n.Flag
		}
		if n.Country != "" && n.Kind != "client" {
			l += " (" + n.Country + ")"
		}
		if n.Kind == "vpn" && n.State != "" {
			l += " [" + n.State + "]"
		}
		label[n.ID] = l
	}
	fmt.Println("# Routing model (per rule)")
	for _, p := range g.Paths {
		mark := " "
		if !p.Enabled {
			mark = "x"
		}
		fmt.Printf("[%s] %-22s %s\n", mark, p.Rule, chainStr(p.Nodes, label))
		if p.Match != "" {
			fmt.Printf("        when: %s -> %s\n", p.Match, p.Action)
		}
	}
	if len(g.Live) == 0 {
		fmt.Println("\n# No live connections")
		return
	}
	fmt.Println("\n# Live traffic")
	for _, l := range g.Live {
		fmt.Printf("%-18s %s\n", l.App, chainStr(l.Nodes, label))
	}
	if !g.GeoEnabled {
		fmt.Println("\n(geo lookups disabled; enable with geo.enabled in config)")
	}
}

func chainStr(ids []string, label map[string]string) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if l, ok := label[id]; ok {
			parts = append(parts, l)
		} else {
			parts = append(parts, strings.TrimPrefix(strings.TrimPrefix(id, "dst:"), "vpn:"))
		}
	}
	return strings.Join(parts, " -> ")
}

func cmdRouteTest(rest []string) {
	fs := flag.NewFlagSet("route-test", flag.ExitOnError)
	app := fs.String("app", "", "process name to attribute")
	port := fs.Int("port", 443, "destination port")
	urlArg := fs.String("url", "", "URL to fetch through the route")
	_ = fs.Parse(rest)
	if fs.NArg() < 1 {
		fatal("usage: cyberboba route-test [-app name] [-port 443] [-url URL] <host>")
	}
	body := map[string]interface{}{"host": fs.Arg(0), "app": *app, "port": *port, "url": *urlArg}
	data := must(call("POST", "/api/route/test", body))
	if *asJSON {
		printJSON(data)
		return
	}
	var d struct {
		Matched               bool
		Rule, Action, Proxy   string
		VPN                   string
		Hops                  []string
		Blocked, Ok           bool
		ExitIP, Country, Flag string
		City, ISP             string
		LatencyMs             int64 `json:"latency_ms"`
		Status                int
		Error                 string
	}
	decode(data, &d)
	path := []string{"this"}
	if d.VPN != "" {
		path = append(path, "vpn:"+d.VPN)
	}
	path = append(path, d.Hops...)
	fmt.Printf("rule:   %s (%s)\n", d.Rule, d.Action)
	fmt.Printf("route:  %s -> dest\n", strings.Join(path, " -> "))
	if d.Blocked {
		fmt.Println("result: BLOCKED by rule")
		return
	}
	if d.Ok {
		fmt.Printf("result: OK  %dms  exit %s %s %s %s  %s\n", d.LatencyMs, d.ExitIP, d.Flag, d.Country, d.City, d.ISP)
	} else {
		fmt.Printf("result: FAILED  %s\n", d.Error)
	}
}

func cmdSysstat(rest []string) {
	data := must(call("GET", "/api/sysstat", nil))
	if *asJSON {
		printJSON(data)
		return
	}
	var d struct {
		CPU struct {
			Pct                  float64
			PerCore              []float64 `json:"per_core"`
			Load1, Load5, Load15 float64
			NCPU                 int
		}
		Mem struct {
			TotalKB  int64   `json:"total_kb"`
			UsedKB   int64   `json:"used_kb"`
			AvailKB  int64   `json:"avail_kb"`
			SwapKB   int64   `json:"swap_total_kb"`
			SwapUsed int64   `json:"swap_used_kb"`
			Pct      float64 `json:"pct"`
			SwapPct  float64 `json:"swap_pct"`
		}
		Temps []struct {
			Chip, Label string
			Celsius     float64
		}
		Fans []struct {
			Chip, Label string
			RPM         int
		}
	}
	decode(data, &d)
	fmt.Printf("CPU:  %.1f%%  (load %.2f %.2f %.2f, %d cores)\n", d.CPU.Pct, d.CPU.Load1, d.CPU.Load5, d.CPU.Load15, d.CPU.NCPU)
	if len(d.CPU.PerCore) > 0 {
		parts := make([]string, len(d.CPU.PerCore))
		for i, c := range d.CPU.PerCore {
			parts[i] = fmt.Sprintf("c%d %.0f%%", i, c)
		}
		fmt.Printf("      %s\n", strings.Join(parts, "  "))
	}
	fmt.Printf("Mem:  %.1f%%  %s / %s used\n", d.Mem.Pct, humanKB(d.Mem.UsedKB), humanKB(d.Mem.TotalKB))
	if d.Mem.SwapKB > 0 {
		fmt.Printf("Swap: %.1f%%  %s / %s\n", d.Mem.SwapPct, humanKB(d.Mem.SwapUsed), humanKB(d.Mem.SwapKB))
	}
	if len(d.Temps) > 0 {
		fmt.Println("Temps:")
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, t := range d.Temps {
			lbl := t.Label
			if lbl == "" {
				lbl = t.Chip
			} else {
				lbl = t.Chip + " / " + lbl
			}
			fmt.Fprintf(tw, "  %s\t%.1f C\n", lbl, t.Celsius)
		}
		tw.Flush()
	}
	for _, f := range d.Fans {
		fmt.Printf("Fan:  %s %d rpm\n", f.Chip, f.RPM)
	}
}

func cmdProcmon(rest []string) {
	all := false
	for _, a := range rest {
		if a == "--all" || a == "-a" {
			all = true
		}
	}
	data := must(call("GET", "/api/procmon", nil))
	if *asJSON {
		printJSON(data)
		return
	}
	var d struct {
		Processes []struct {
			PID, PPID, Threads, Conns int
			Name, User, State, Cmd    string
			CPUPct                    float64 `json:"cpu_pct"`
			RSSKB                     int64   `json:"rss_kb"`
			System                    bool
		}
		Summary struct {
			Total, System, User int
			CPUPct              float64 `json:"cpu_pct"`
			RSSKB               int64   `json:"rss_kb"`
		}
	}
	decode(data, &d)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PID\tUSER\tCPU%\tMEM\tTHR\tNET\tSTATE\tNAME")
	n := 0
	for _, p := range d.Processes {
		if p.System && !all {
			continue
		}
		net := ""
		if p.Conns > 0 {
			net = fmt.Sprintf("%d", p.Conns)
		}
		fmt.Fprintf(tw, "%d\t%s\t%.1f\t%s\t%d\t%s\t%s\t%s\n", p.PID, p.User, p.CPUPct, humanKB(p.RSSKB), p.Threads, net, p.State, p.Name)
		n++
	}
	tw.Flush()
	fmt.Printf("\n%d shown (%d total: %d user, %d system) · CPU %.1f%% · RSS %s\n", n, d.Summary.Total, d.Summary.User, d.Summary.System, d.Summary.CPUPct, humanKB(d.Summary.RSSKB))
	if !all {
		fmt.Println("(system/service processes hidden; use --all to show)")
	}
}

func humanKB(kb int64) string {
	f := float64(kb)
	switch {
	case f >= 1024*1024:
		return fmt.Sprintf("%.1fG", f/1024/1024)
	case f >= 1024:
		return fmt.Sprintf("%.1fM", f/1024)
	default:
		return fmt.Sprintf("%dK", kb)
	}
}

func cmdKill(rest []string) {
	if len(rest) < 1 {
		fatal("usage: cyberboba kill <pid> [KILL|TERM|HUP]")
	}
	sig := "TERM"
	if len(rest) > 1 {
		sig = rest[1]
	}
	printJSON(must(call("POST", "/api/processes/"+rest[0]+"/kill", map[string]string{"signal": sig})))
}

func cmdReclaim(rest []string) {
	fs := flag.NewFlagSet("reclaim", flag.ExitOnError)
	caches := fs.Bool("caches", true, "drop page cache / dentries / inodes")
	swap := fs.Bool("swap", false, "cycle swap back into RAM (swapoff -a && swapon -a)")
	compact := fs.Bool("compact", false, "compact (defragment) memory")
	all := fs.Bool("all", false, "do everything: caches + compact + swap")
	_ = fs.Parse(rest)
	if *all {
		*caches, *compact, *swap = true, true, true
	}
	data := must(call("POST", "/api/system/reclaim", map[string]bool{"caches": *caches, "swap": *swap, "compact": *compact}))
	if *asJSON {
		printJSON(data)
		return
	}
	var d struct {
		Actions     []string
		Warnings    []string
		FreedKB     int64 `json:"freed_kb"`
		SwapFreedKB int64 `json:"swap_freed_kb"`
	}
	decode(data, &d)
	for _, a := range d.Actions {
		fmt.Printf("  ok   %s\n", a)
	}
	for _, w := range d.Warnings {
		fmt.Printf("  skip %s\n", w)
	}
	fmt.Printf("freed %s RAM", humanKB(d.FreedKB))
	if d.SwapFreedKB != 0 {
		fmt.Printf(", %s swap", humanKB(d.SwapFreedKB))
	}
	fmt.Println()
}

func cmdBandwidth(rest []string) {
	if len(rest) > 0 && rest[0] == "reset" {
		printJSON(must(call("POST", "/api/bandwidth/reset", nil)))
		return
	}
	if len(rest) > 0 && rest[0] == "daily" {
		printJSON(must(call("GET", "/api/bandwidth/daily", nil)))
		return
	}
	if len(rest) > 0 && rest[0] == "alerts" {
		printJSON(must(call("GET", "/api/bandwidth/alerts", nil)))
		return
	}
	data := must(call("GET", "/api/bandwidth", nil))
	if *asJSON {
		printJSON(data)
		return
	}
	var d struct {
		Apps []struct {
			App      string
			RateIn   float64 `json:"rate_in"`
			RateOut  float64 `json:"rate_out"`
			TotalIn  int64   `json:"total_in"`
			TotalOut int64   `json:"total_out"`
			TodayIn  int64   `json:"today_in"`
			TodayOut int64   `json:"today_out"`
			Conns    int
		}
		TotalRateIn  float64 `json:"total_rate_in"`
		TotalRateOut float64 `json:"total_rate_out"`
		TotalTodayIn int64   `json:"total_today_in"`
	}
	// decode with correct json tags
	decode(data, &d)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "APP	DOWN	UP	TODAY↓	TODAY↑	SESSION↓	SESSION↑	CONNS")
	for _, a := range d.Apps {
		fmt.Fprintf(tw, "%s\t%s/s\t%s/s\t%s\t%s\t%s\t%s\t%d\n", a.App,
			fmtBytes(a.RateIn), fmtBytes(a.RateOut),
			fmtBytes(float64(a.TodayIn)), fmtBytes(float64(a.TodayOut)),
			fmtBytes(float64(a.TotalIn)), fmtBytes(float64(a.TotalOut)), a.Conns)
	}
	tw.Flush()
	fmt.Printf("total: %s/s down · %s/s up · today %s down\n", fmtBytes(d.TotalRateIn), fmtBytes(d.TotalRateOut), fmtBytes(float64(d.TotalTodayIn)))
}

func cmdAutostart(rest []string) {
	if len(rest) > 0 {
		switch rest[0] {
		case "on", "enable":
			printJSON(must(call("POST", "/api/system/autostart", map[string]interface{}{"enabled": true})))
			return
		case "off", "disable":
			printJSON(must(call("POST", "/api/system/autostart", map[string]interface{}{"enabled": false})))
			return
		}
	}
	data := must(call("GET", "/api/system/autostart", nil))
	if *asJSON {
		printJSON(data)
		return
	}
	var d struct {
		ServiceEnabled bool     `json:"service_enabled"`
		ServiceActive  bool     `json:"service_active"`
		VPNAutostart   []string `json:"vpn_autostart"`
		CanManage      bool     `json:"can_manage"`
		Unit           string   `json:"unit"`
	}
	decode(data, &d)
	onoff := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	fmt.Printf("start on boot: %s · running now: %s · unit: %s\n", onoff(d.ServiceEnabled), onoff(d.ServiceActive), d.Unit)
	if len(d.VPNAutostart) > 0 {
		fmt.Printf("auto-connect VPNs: %s\n", strings.Join(d.VPNAutostart, ", "))
	} else {
		fmt.Println("auto-connect VPNs: (none set — tick \"Autostart\" on a VPN)")
	}
	if !d.CanManage {
		fmt.Println("note: cannot change boot autostart (needs systemd + daemon running as root)")
	}
}

func cmdAI(rest []string) {
	if len(rest) > 0 {
		switch rest[0] {
		case "monitor", "watch":
			printJSON(must(call("POST", "/api/ai/monitor", nil)))
			return
		case "unmonitor", "unwatch", "stop":
			printJSON(must(call("DELETE", "/api/ai/monitor", nil)))
			return
		case "log":
			printJSON(must(call("GET", "/api/ai/log", nil)))
			return
		}
	}
	data := must(call("GET", "/api/ai", nil))
	if *asJSON {
		printJSON(data)
		return
	}
	var d struct {
		Monitoring bool `json:"monitoring"`
		Summary    struct {
			AgentsActive  int `json:"agents_active"`
			AgentsRunning int `json:"agents_running"`
			TotalLeaks    int `json:"total_leaks"`
			TotalFlows    int `json:"total_flows"`
		} `json:"summary"`
		Agents []struct {
			Name      string              `json:"name"`
			Vendor    string              `json:"vendor"`
			Running   []struct{ PID int } `json:"running"`
			LiveConns int                 `json:"live_conns"`
			Flows     int                 `json:"flows"`
			LeakCount int                 `json:"leak_count"`
			Leaks     []struct {
				Title    string `json:"title"`
				Severity string `json:"severity"`
				Host     string `json:"host"`
			} `json:"leaks"`
		} `json:"agents"`
	}
	decode(data, &d)
	mon := "off"
	if d.Monitoring {
		mon = "on"
	}
	fmt.Printf("AI agents — monitoring %s · %d active, %d running · %d flows · %d credential leak(s)\n",
		mon, d.Summary.AgentsActive, d.Summary.AgentsRunning, d.Summary.TotalFlows, d.Summary.TotalLeaks)
	if len(d.Agents) == 0 {
		fmt.Println("no known AI agents running or seen on the network")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "AGENT\tVENDOR\tPROCS\tCONNS\tFLOWS\tLEAKS")
	for _, a := range d.Agents {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\n", a.Name, a.Vendor, len(a.Running), a.LiveConns, a.Flows, a.LeakCount)
	}
	tw.Flush()
	for _, a := range d.Agents {
		for _, l := range a.Leaks {
			fmt.Printf("  ⚠ %s [%s]: %s → %s\n", a.Name, l.Severity, l.Title, l.Host)
		}
	}
}

func cmdDNS(rest []string) {
	if len(rest) == 0 {
		data := must(call("GET", "/api/dns", nil))
		if *asJSON {
			printJSON(data)
			return
		}
		var d struct {
			Stats struct {
				Enabled     bool
				ListDomains int     `json:"list_domains"`
				ManualBlock int     `json:"manual_block"`
				Total       int64   `json:"total_queries"`
				Blocked     int64   `json:"blocked_queries"`
				BlockedPct  float64 `json:"blocked_pct"`
				TopBlocked  []struct {
					Name  string
					Count int64
				} `json:"top_blocked"`
			}
		}
		decode(data, &d)
		st := d.Stats
		fmt.Printf("DNS filter: %v  ·  %d list domains + %d manual\n", onoffStr(st.Enabled), st.ListDomains, st.ManualBlock)
		fmt.Printf("queries: %d  ·  blocked: %d (%.1f%%)\n", st.Total, st.Blocked, st.BlockedPct)
		if len(st.TopBlocked) > 0 {
			fmt.Println("top blocked:")
			for i, b := range st.TopBlocked {
				if i >= 8 {
					break
				}
				fmt.Printf("  %-40s %d\n", b.Name, b.Count)
			}
		}
		return
	}
	switch rest[0] {
	case "log":
		blocked := len(rest) > 1 && (rest[1] == "--blocked" || rest[1] == "-b")
		path := "/api/dns/log?limit=100"
		if blocked {
			path += "&blocked=1"
		}
		data := must(call("GET", path, nil))
		if *asJSON {
			printJSON(data)
			return
		}
		var v struct {
			Queries []struct {
				At      time.Time
				Name    string
				Type    string
				Blocked bool
			}
		}
		decode(data, &v)
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, q := range v.Queries {
			mark := " "
			if q.Blocked {
				mark = "BLOCK"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", q.At.Format("15:04:05"), mark, q.Type, q.Name)
		}
		tw.Flush()
	case "block":
		if len(rest) < 2 {
			fatal("usage: cyberboba dns block <domain>")
		}
		printJSON(must(call("POST", "/api/dns/block", map[string]string{"domain": rest[1]})))
	case "unblock":
		if len(rest) < 2 {
			fatal("usage: cyberboba dns unblock <domain>")
		}
		printJSON(must(call("POST", "/api/dns/unblock", map[string]string{"domain": rest[1]})))
	case "refresh":
		printJSON(must(call("POST", "/api/dns/refresh", nil)))
	case "reset":
		printJSON(must(call("POST", "/api/dns/reset", nil)))
	case "on", "off":
		cur := map[string]interface{}{}
		decode(must(call("GET", "/api/dns", nil)), &struct{}{})
		cur["enabled"] = rest[0] == "on"
		printJSON(must(call("PUT", "/api/dns", cur)))
	default:
		fatal("usage: cyberboba dns [log|block|unblock|refresh|reset|on|off]")
	}
}

func onoffStr(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}

func cmdFirewall(rest []string) {
	if len(rest) == 0 {
		data := must(call("GET", "/api/firewall", nil))
		if *asJSON {
			printJSON(data)
			return
		}
		var d struct {
			Enabled      bool
			Mode         string
			Stealth      bool
			InternetLock bool `json:"internet_lock"`
			Pending      int
			Programs     int
			Stats        map[string]int
		}
		decode(data, &d)
		fmt.Printf("firewall: enabled=%v mode=%s stealth=%v internet_lock=%v\n", d.Enabled, d.Mode, d.Stealth, d.InternetLock)
		fmt.Printf("programs=%d pending=%d  allowed=%d blocked=%d asked=%d\n", d.Programs, d.Pending, d.Stats["allowed"], d.Stats["blocked"], d.Stats["asked"])
		return
	}
	switch rest[0] {
	case "mode":
		if len(rest) < 2 {
			fatal("usage: cyberboba firewall mode <off|ask|auto|block>")
		}
		printJSON(must(call("POST", "/api/firewall/mode", map[string]string{"mode": rest[1]})))
	case "lock", "stealth", "enable":
		on := len(rest) > 1 && (rest[1] == "on" || rest[1] == "true")
		printJSON(must(call("POST", "/api/firewall/"+rest[0], map[string]bool{"on": on})))
	case "activity", "log", "recent":
		blocked := false
		for _, a := range rest[1:] {
			if a == "--blocked" || a == "-b" || a == "blocked" {
				blocked = true
			}
		}
		path := "/api/firewall/activity?limit=200"
		if blocked {
			path += "&blocked=1"
		}
		data := must(call("GET", path, nil))
		if *asJSON {
			printJSON(data)
			return
		}
		var d struct {
			Activity []struct {
				Time                time.Time
				App, Host, IP, Zone string
				Port                int
				Allow               bool
				Reason              string
			}
		}
		decode(data, &d)
		if len(d.Activity) == 0 {
			fmt.Println("(no firewall activity recorded yet)")
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "TIME\tACTION\tAPP\tZONE\tDESTINATION\tREASON")
		for _, a := range d.Activity {
			act := "BLOCK"
			if a.Allow {
				act = "allow"
			}
			dst := a.Host
			if dst == "" {
				dst = a.IP
			}
			if a.Port != 0 {
				dst = fmt.Sprintf("%s:%d", dst, a.Port)
			}
			app := a.App
			if app == "" {
				app = "unknown"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", a.Time.Format("15:04:05"), act, app, a.Zone, dst, a.Reason)
		}
		tw.Flush()
		return
	case "pending":
		data := must(call("GET", "/api/firewall/pending", nil))
		if *asJSON {
			printJSON(data)
			return
		}
		var d struct {
			Pending []struct {
				ID                  uint64
				App, Host, IP, Zone string
				Port                int
			}
		}
		decode(data, &d)
		if len(d.Pending) == 0 {
			fmt.Println("(no pending firewall prompts)")
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tAPP\tZONE\tDESTINATION")
		for _, a := range d.Pending {
			dst := a.Host
			if dst == "" {
				dst = a.IP
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s:%d\n", a.ID, a.App, a.Zone, dst, a.Port)
		}
		tw.Flush()
	case "allow", "deny":
		if len(rest) < 2 {
			fatal("usage: cyberboba firewall allow|deny <id> [remember]")
		}
		var id uint64
		fmt.Sscanf(rest[1], "%d", &id)
		remember := len(rest) > 2 && rest[2] == "remember"
		printJSON(must(call("POST", "/api/firewall/answer", map[string]interface{}{"id": id, "allow": rest[0] == "allow", "remember": remember})))
	case "allow-all", "deny-all":
		printJSON(must(call("POST", "/api/firewall/answer_all", map[string]bool{"allow": rest[0] == "allow-all"})))
	case "block", "unblock":
		if len(rest) < 2 {
			fatal("usage: cyberboba firewall block|unblock <host|*.domain|ip|cidr>")
		}
		printJSON(must(call("POST", "/api/firewall/"+rest[0], map[string]string{"host": rest[1]})))
	case "blocked":
		printJSON(must(call("GET", "/api/firewall/blocked", nil)))
	default:
		fatal("usage: cyberboba firewall [mode|lock|stealth|enable|activity|pending|allow|deny|allow-all|deny-all|block|unblock|blocked]")
	}
}

func cmdApps(rest []string) {
	data := must(call("GET", "/api/apps/installed", nil))
	if *asJSON {
		printJSON(data)
		return
	}
	var d struct {
		Apps []struct{ Name, Binary, Keyword string }
	}
	decode(data, &d)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tBINARY\tMATCH")
	for _, a := range d.Apps {
		fmt.Fprintf(tw, "%s\t%s\tcmd:%s\n", a.Name, a.Binary, a.Keyword)
	}
	tw.Flush()
}

func cmdGeo(rest []string) {
	if len(rest) < 1 {
		fatal("usage: cyberboba geo <ip-or-host>")
	}
	data := must(call("GET", "/api/geo/"+rest[0], nil))
	if *asJSON {
		printJSON(data)
		return
	}
	var info struct{ IP, Country, CC, City, ISP, Flag string }
	decode(data, &info)
	fmt.Printf("%s %s  %s %s  %s\n", info.IP, info.Flag, info.Country, info.City, info.ISP)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}

func cmdStatus() {
	data := must(call("GET", "/api/status", nil))
	if *asJSON {
		printJSON(data)
		return
	}
	var v struct {
		Version   string
		UptimeSec int `json:"uptime_sec"`
		Proxify   struct {
			Enabled            bool
			NetfilterInstalled bool   `json:"netfilter_installed"`
			ListenTCP          string `json:"listen_tcp"`
		}
		Stats struct {
			Active   int
			Total    uint64
			Blocked  uint64
			BytesIn  float64 `json:"bytes_in"`
			BytesOut float64 `json:"bytes_out"`
			RateIn   float64 `json:"rate_in"`
			RateOut  float64 `json:"rate_out"`
		}
		VPNs []struct {
			Name      string
			State     string
			Interface string
			LocalIP   string `json:"local_ip"`
			Mode      string
			RxBytes   float64 `json:"rx_bytes"`
			TxBytes   float64 `json:"tx_bytes"`
			Error     string
		} `json:"vpns"`
		Caido struct {
			Enabled, Running, Reachable bool
			Listen, Version, Error      string
		}
		Warnings []string
	}
	decode(data, &v)
	fmt.Printf("cyberbobad %s, up %s\n", v.Version, (time.Duration(v.UptimeSec) * time.Second).String())
	state := "OFF"
	if v.Proxify.NetfilterInstalled {
		state = "ON"
	}
	fmt.Printf("proxify: %s (listener %s)\n", state, v.Proxify.ListenTCP)
	fmt.Printf("connections: %d active, %d total, %d blocked; in %s (%s/s) out %s (%s/s)\n",
		v.Stats.Active, v.Stats.Total, v.Stats.Blocked, fmtBytes(v.Stats.BytesIn), fmtBytes(v.Stats.RateIn), fmtBytes(v.Stats.BytesOut), fmtBytes(v.Stats.RateOut))
	for _, x := range v.VPNs {
		fmt.Printf("vpn %-16s %-10s %-8s iface=%s ip=%s %s\n", x.Name, x.State, x.Mode, x.Interface, x.LocalIP, x.Error)
	}
	if v.Caido.Enabled {
		st := "stopped"
		if v.Caido.Running {
			st = "running"
		}
		if v.Caido.Reachable {
			st += ", reachable"
		}
		fmt.Printf("caido: %s on %s %s %s\n", st, v.Caido.Listen, v.Caido.Version, v.Caido.Error)
	}
	for _, w := range v.Warnings {
		fmt.Println("warning:", w)
	}
}

type conn struct {
	ID       uint64
	Started  time.Time
	State    string
	PID      int
	App      string
	User     string
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
	Host     string
	Rule     string
	Action   string
	Via      string
	BytesIn  float64 `json:"bytes_in"`
	BytesOut float64 `json:"bytes_out"`
	Error    string
}

func (c conn) target() string {
	if c.Host != "" {
		return fmt.Sprintf("%s:%d", c.Host, c.DstPort)
	}
	return net.JoinHostPort(c.DstIP, strconv.Itoa(c.DstPort))
}

func printConn(w io.Writer, c conn) {
	via := c.Via
	if via == "" {
		via = "-"
	}
	fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.Started.Format("15:04:05"), c.ID, c.App, c.User, c.target(),
		c.Rule, c.Action, via, fmtBytes(c.BytesIn), fmtBytes(c.BytesOut), c.State+" "+c.Error)
}

func cmdConns(rest []string) {
	fs := flag.NewFlagSet("conns", flag.ExitOnError)
	closed := fs.Bool("closed", false, "include closed connections")
	follow := fs.Bool("follow", false, "stream new connections")
	limit := fs.Int("limit", 200, "max rows")
	_ = fs.Parse(rest)
	q := fmt.Sprintf("/api/connections?limit=%d&closed=%d", *limit, b2i(*closed))
	data := must(call("GET", q, nil))
	if *asJSON && !*follow {
		printJSON(data)
		return
	}
	var v struct{ Connections []conn }
	decode(data, &v)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tID\tAPP\tUSER\tTARGET\tRULE\tACTION\tVIA\tIN\tOUT\tSTATE")
	for i := len(v.Connections) - 1; i >= 0; i-- {
		printConn(tw, v.Connections[i])
	}
	tw.Flush()
	if !*follow {
		return
	}
	streamEvents(func(typ string, data []byte) {
		if typ != "conn" {
			return
		}
		var c conn
		if json.Unmarshal(data, &c) == nil && (c.State == "open" || c.State == "blocked" || c.State == "error") {
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			printConn(tw, c)
			tw.Flush()
		}
	})
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func streamEvents(fn func(typ string, data []byte)) {
	base := "http://cyberboba"
	if *api != "" {
		base = "http://" + *api
	}
	req, _ := http.NewRequest("GET", base+"/api/events", nil)
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	cl := client()
	cl.Timeout = 0
	resp, err := cl.Do(req)
	if err != nil {
		fatal("cannot stream events: " + err.Error())
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	typ := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			typ = line[7:]
		case strings.HasPrefix(line, "data: "):
			fn(typ, []byte(line[6:]))
		}
	}
}

func cmdRules(rest []string) {
	if len(rest) >= 3 && rest[0] == "test" {
		host, port := rest[2], 443
		if h, p, err := net.SplitHostPort(rest[2]); err == nil {
			host = h
			port, _ = strconv.Atoi(p)
		}
		body := map[string]interface{}{"app": rest[1], "host": host, "port": port}
		if net.ParseIP(host) != nil {
			body["ip"] = host
			body["host"] = ""
		}
		data := must(call("POST", "/api/rules/test", body))
		printJSON(data)
		return
	}
	data := must(call("GET", "/api/rules", nil))
	if *asJSON {
		printJSON(data)
		return
	}
	var v struct {
		Rules []struct {
			Name                                   string
			Enabled                                *bool
			Apps, Users, Targets, Ports, Protocols []string
			Action, Proxy, VPN                     string
		}
	}
	decode(data, &v)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tON\tNAME\tAPPS\tTARGETS\tPORTS\tACTION")
	for i, r := range v.Rules {
		on := "y"
		if r.Enabled != nil && !*r.Enabled {
			on = "n"
		}
		act := r.Action
		if r.Proxy != "" {
			act += ":" + r.Proxy
		}
		if r.VPN != "" {
			act += ":" + r.VPN
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", i, on, r.Name, orAny(r.Apps), orAny(r.Targets), orAny(r.Ports), act)
	}
	tw.Flush()
}

func orAny(s []string) string {
	if len(s) == 0 {
		return "*"
	}
	return strings.Join(s, ",")
}

func cmdProxies(rest []string) {
	if len(rest) >= 2 && rest[0] == "check" {
		body := map[string]string{}
		if len(rest) > 2 {
			body["url"] = rest[2]
		}
		printJSON(must(call("POST", "/api/proxies/"+rest[1]+"/check", body)))
		return
	}
	data := must(call("GET", "/api/proxies", nil))
	if *asJSON {
		printJSON(data)
		return
	}
	var v struct {
		Proxies []struct {
			Name   string
			Type   string
			Addr   string
			ViaVPN string `json:"via_vpn"`
			Hops   []string
		}
	}
	decode(data, &v)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTYPE\tADDR\tHOPS\tVIA VPN")
	for _, p := range v.Proxies {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Type, p.Addr, strings.Join(p.Hops, ","), p.ViaVPN)
	}
	tw.Flush()
}

func cmdVPN(rest []string) {
	if len(rest) == 0 {
		data := must(call("GET", "/api/vpn", nil))
		if *asJSON {
			printJSON(data)
			return
		}
		var v struct {
			VPNs []struct {
				Name      string
				Type      string
				Mode      string
				State     string
				Interface string
				Endpoint  string
				LocalIP   string `json:"local_ip"`
				Error     string
				RxBytes   float64 `json:"rx_bytes"`
				TxBytes   float64 `json:"tx_bytes"`
			} `json:"vpns"`
		}
		decode(data, &v)
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tTYPE\tMODE\tSTATE\tIFACE\tLOCAL IP\tENDPOINT\tRX\tTX\tERROR")
		for _, x := range v.VPNs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", x.Name, x.Type, x.Mode, x.State, x.Interface, x.LocalIP, x.Endpoint, fmtBytes(x.RxBytes), fmtBytes(x.TxBytes), x.Error)
		}
		tw.Flush()
		return
	}
	switch rest[0] {
	case "up", "down":
		if len(rest) < 2 {
			fatal("usage: cyberboba vpn up|down <name>")
		}
		printJSON(must(call("POST", "/api/vpn/"+rest[1]+"/"+rest[0], nil)))
	case "log":
		if len(rest) < 2 {
			fatal("usage: cyberboba vpn log <name>")
		}
		var v struct{ Lines []string }
		decode(must(call("GET", "/api/vpn/"+rest[1]+"/log", nil)), &v)
		fmt.Println(strings.Join(v.Lines, "\n"))
	case "import":
		fs := flag.NewFlagSet("import", flag.ExitOnError)
		typ := fs.String("type", "", "wireguard|openvpn (auto)")
		mode := fs.String("mode", "selective", "full|selective")
		_ = fs.Parse(rest[1:])
		if fs.NArg() < 2 {
			fatal("usage: cyberboba vpn import <name> <file> [-type t] [-mode m]")
		}
		content, err := os.ReadFile(fs.Arg(1))
		if err != nil {
			fatal(err.Error())
		}
		printJSON(must(call("POST", "/api/vpn/import", map[string]string{"name": fs.Arg(0), "type": *typ, "mode": *mode, "content": string(content)})))
	default:
		fatal("usage: cyberboba vpn [up|down|log|import] ...")
	}
}

func cmdCaido(rest []string) {
	if len(rest) == 0 {
		printJSON(must(call("GET", "/api/caido", nil)))
		return
	}
	switch rest[0] {
	case "start", "stop", "restart", "install":
		if rest[0] == "install" {
			fmt.Fprintln(os.Stderr, "downloading latest caido-cli ...")
		}
		printJSON(must(call("POST", "/api/caido/"+rest[0], nil)))
	case "log":
		var v struct{ Lines []string }
		decode(must(call("GET", "/api/caido/log", nil)), &v)
		fmt.Println(strings.Join(v.Lines, "\n"))
	case "ca-install":
		body := map[string]string{}
		if len(rest) > 1 {
			abs, _ := absPath(rest[1])
			body["path"] = abs
		}
		printJSON(must(call("POST", "/api/caido/ca/install", body)))
	default:
		fatal("usage: cyberboba caido [start|stop|restart|install|log|ca-install]")
	}
}

func absPath(p string) (string, error) {
	if strings.HasPrefix(p, "/") {
		return p, nil
	}
	wd, err := os.Getwd()
	return wd + "/" + p, err
}

func cmdConfig(rest []string) {
	if len(rest) == 2 && rest[0] == "apply" {
		b, err := os.ReadFile(rest[1])
		if err != nil {
			fatal(err.Error())
		}
		must(call("PUT", "/api/config/yaml", string(b)))
		fmt.Println("applied")
		return
	}
	if *asJSON {
		printJSON(must(call("GET", "/api/config", nil)))
		return
	}
	data := must(call("GET", "/api/config/yaml", nil))
	os.Stdout.Write(data)
}

func cmdRun(rest []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	tag := fs.String("tag", "", "tag visible to rules as tag:NAME")
	_ = fs.Parse(rest)
	if fs.NArg() == 0 {
		fatal("usage: cyberboba run -tag NAME -- command [args]")
	}
	if *tag == "" {
		*tag = fs.Arg(0)
	}
	path, err := exec.LookPath(fs.Arg(0))
	if err != nil {
		fatal(err.Error())
	}
	// Attach this process to the tag's net_cls cgroup before exec so that
	// its UDP traffic (QUIC, games, VoIP) can be policed by tag rules. The
	// cgroup membership and CYBERBOBA_TAG env survive the exec. Best effort:
	// if the daemon has no cgroup support the TCP tag rules still work.
	if _, err := call("POST", "/api/tags/attach", map[string]interface{}{"pid": os.Getpid(), "tag": *tag}); err != nil {
		fmt.Fprintln(os.Stderr, "note: UDP tagging unavailable:", err)
	}
	env := append(os.Environ(), "CYBERBOBA_TAG="+*tag)
	if err := syscall.Exec(path, fs.Args(), env); err != nil {
		fatal(err.Error())
	}
}

func cmdLog(rest []string) {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	follow := fs.Bool("follow", false, "stream")
	_ = fs.Parse(rest)
	var v struct {
		Lines []struct {
			Time       time.Time
			Level, Msg string
		}
	}
	decode(must(call("GET", "/api/log?limit=500", nil)), &v)
	for _, l := range v.Lines {
		fmt.Printf("%s [%s] %s\n", l.Time.Format("15:04:05"), l.Level, l.Msg)
	}
	if *follow {
		streamEvents(func(typ string, data []byte) {
			if typ == "log" {
				var l struct {
					Time       time.Time
					Level, Msg string
				}
				if json.Unmarshal(data, &l) == nil {
					fmt.Printf("%s [%s] %s\n", l.Time.Format("15:04:05"), l.Level, l.Msg)
				}
			}
		})
	}
}

var _ = sort.Strings

func cmdIntercept(rest []string) {
	if len(rest) == 0 {
		printJSON(must(call("GET", "/api/intercept", nil)))
		return
	}
	onoff := func(v string) bool { return v == "on" || v == "true" || v == "1" }
	switch rest[0] {
	case "on", "off":
		printJSON(must(call("POST", "/api/intercept/toggle", map[string]bool{"recording": onoff(rest[0])})))
	case "record":
		if len(rest) < 2 {
			// list currently-recorded apps
			data := must(call("GET", "/api/intercept/record", nil))
			if *asJSON {
				printJSON(data)
				return
			}
			var d struct {
				Apps      []string
				Recording bool
			}
			decode(data, &d)
			if len(d.Apps) == 0 {
				fmt.Println("recording no specific apps (add one: cyberboba intercept record <app>)")
			} else {
				fmt.Printf("recording apps: %s  (recording %v)\n", strings.Join(d.Apps, ", "), d.Recording)
			}
			return
		}
		printJSON(must(call("POST", "/api/intercept/record", map[string]string{"app": rest[1]})))
	case "unrecord", "record-stop":
		if len(rest) < 2 {
			fatal("usage: cyberboba intercept unrecord <app>")
		}
		printJSON(must(call("DELETE", "/api/intercept/record?app="+urlQ(rest[1]), nil)))
	case "scan":
		if len(rest) < 2 {
			fatal("usage: cyberboba intercept scan on|off")
		}
		printJSON(must(call("POST", "/api/intercept/toggle", map[string]bool{"scan": onoff(rest[1])})))
	case "findings":
		data := must(call("GET", "/api/intercept/findings", nil))
		if *asJSON {
			printJSON(data)
			return
		}
		var v struct {
			Groups []struct {
				Rule, Title, Severity string
				Count                 int
			}
			Severity     map[string]int
			ScannedFlows int `json:"scanned_flows"`
		}
		decode(data, &v)
		fmt.Printf("scanned %d flows — high %d · medium %d · low %d · info %d\n", v.ScannedFlows,
			v.Severity["high"], v.Severity["medium"], v.Severity["low"], v.Severity["info"])
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, g := range v.Groups {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", strings.ToUpper(g.Severity), g.Title, g.Count, g.Rule)
		}
		tw.Flush()
	case "hold-req", "hold-resp":
		if len(rest) < 2 {
			fatal("usage: cyberboba intercept hold-req on|off")
		}
		key := "hold_requests"
		if rest[0] == "hold-resp" {
			key = "hold_responses"
		}
		printJSON(must(call("POST", "/api/intercept/toggle", map[string]bool{key: onoff(rest[1])})))
	case "flows":
		fs := flag.NewFlagSet("flows", flag.ExitOnError)
		q := fs.String("q", "", "substring")
		host := fs.String("host", "", "host filter")
		status := fs.String("status", "", "status or prefix")
		limit := fs.Int("limit", 50, "max rows")
		scope := fs.Bool("scope", false, "in-scope only")
		_ = fs.Parse(rest[1:])
		path := fmt.Sprintf("/api/intercept/flows?limit=%d&q=%s&host=%s&status=%s&scope=%d", *limit, urlQ(*q), urlQ(*host), urlQ(*status), b2i(*scope))
		data := must(call("GET", path, nil))
		if *asJSON {
			printJSON(data)
			return
		}
		var v struct {
			Flows []struct {
				ID                  uint64
				Time                time.Time
				App, Method, URL    string
				Status              int
				RespSize            int64  `json:"resp_size"`
				ContentType         string `json:"content_type"`
				DurationMS          int64  `json:"duration_ms"`
				State               string
				Intercepted, Edited bool
			}
			Total int
		}
		decode(data, &v)
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTIME\tAPP\tMETHOD\tURL\tSTATUS\tSIZE\tTYPE\tMS\tSTATE")
		for _, f := range v.Flows {
			u := f.URL
			if len(u) > 80 {
				u = u[:77] + "..."
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%d\t%s\n", f.ID, f.Time.Format("15:04:05"), f.App, f.Method, u, f.Status, fmtBytes(float64(f.RespSize)), f.ContentType, f.DurationMS, f.State)
		}
		tw.Flush()
		fmt.Fprintf(os.Stderr, "%d of %d flows\n", len(v.Flows), v.Total)
	case "flow":
		if len(rest) < 2 {
			fatal("usage: cyberboba intercept flow <id> [-raw]")
		}
		data := must(call("GET", "/api/intercept/flows/"+rest[1], nil))
		if len(rest) > 2 && rest[2] == "-raw" {
			var v struct {
				ReqRaw  string `json:"req_raw"`
				RespRaw string `json:"resp_raw"`
			}
			decode(data, &v)
			fmt.Println(v.ReqRaw)
			fmt.Println()
			fmt.Println(v.RespRaw)
			return
		}
		printJSON(data)
	case "pending":
		printJSON(must(call("GET", "/api/intercept/pending", nil)))
	case "forward":
		if len(rest) < 2 {
			fatal("usage: cyberboba intercept forward <id> [edited-file]")
		}
		body := map[string]string{}
		if len(rest) > 2 {
			b, err := os.ReadFile(rest[2])
			if err != nil {
				fatal(err.Error())
			}
			body["raw"] = string(b)
		}
		printJSON(must(call("POST", "/api/intercept/pending/"+rest[1]+"/forward", body)))
	case "drop":
		if len(rest) < 2 {
			fatal("usage: cyberboba intercept drop <id>")
		}
		printJSON(must(call("POST", "/api/intercept/pending/"+rest[1]+"/drop", nil)))
	case "forward-all":
		printJSON(must(call("POST", "/api/intercept/pending/forward-all", nil)))
	case "send":
		fs := flag.NewFlagSet("send", flag.ExitOnError)
		host := fs.String("host", "", "target host")
		port := fs.Int("port", 0, "target port")
		useTLS := fs.Bool("tls", false, "use TLS")
		follow := fs.Bool("follow", false, "follow redirects")
		_ = fs.Parse(rest[1:])
		var raw []byte
		var err error
		if fs.NArg() == 0 || fs.Arg(0) == "-" {
			raw, err = io.ReadAll(os.Stdin)
		} else {
			raw, err = os.ReadFile(fs.Arg(0))
		}
		if err != nil {
			fatal(err.Error())
		}
		data := must(call("POST", "/api/intercept/send", map[string]interface{}{"host": *host, "port": *port, "tls": *useTLS, "raw": string(raw), "follow_redirects": *follow}))
		if *asJSON {
			printJSON(data)
			return
		}
		var v struct {
			Flow struct {
				RespRaw string `json:"resp_raw"`
				Error   string
			}
			Error string
		}
		decode(data, &v)
		if v.Error != "" {
			fatal(v.Error)
		}
		fmt.Println(v.Flow.RespRaw)
	case "ca":
		if len(rest) > 1 && rest[1] == "install" {
			printJSON(must(call("POST", "/api/intercept/ca/install", nil)))
			return
		}
		if len(rest) > 1 && rest[1] == "path" {
			var v struct {
				CACert string `json:"ca_cert"`
			}
			decode(must(call("GET", "/api/intercept", nil)), &v)
			fmt.Println(v.CACert)
			return
		}
		os.Stdout.Write(must(call("GET", "/api/intercept/ca", nil)))
	case "export":
		fs := flag.NewFlagSet("export", flag.ExitOnError)
		out := fs.String("o", "", "output file (default stdout)")
		_ = fs.Parse(rest[1:])
		data := must(call("GET", "/api/intercept/export?format=har", nil))
		if *out == "" {
			os.Stdout.Write(data)
			return
		}
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			fatal(err.Error())
		}
		fmt.Println("wrote", *out)
	default:
		fatal("unknown intercept subcommand " + rest[0])
	}
}

func urlQ(s string) string {
	return strings.NewReplacer("&", "%26", " ", "%20", "#", "%23", "+", "%2B").Replace(s)
}
