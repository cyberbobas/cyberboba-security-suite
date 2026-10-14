// Package app wires all components of the daemon together.
package app

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cyberboba/internal/bandwidth"
	"cyberboba/internal/caido"
	"cyberboba/internal/config"
	"cyberboba/internal/dnsfwd"
	"cyberboba/internal/firewall"
	"cyberboba/internal/geo"
	"cyberboba/internal/intercept"
	"cyberboba/internal/netfilter"
	"cyberboba/internal/procinfo"
	"cyberboba/internal/procmon"
	"cyberboba/internal/proxy"
	"cyberboba/internal/rules"
	"cyberboba/internal/stats"
	"cyberboba/internal/sysstat"
	"cyberboba/internal/tags"
	"cyberboba/internal/upstream"
	"cyberboba/internal/vpn"
)

// Version of the build; overridden via -ldflags.
var Version = "0.2.0"

// Daemon is the running application.
type Daemon struct {
	Store     *config.Store
	Tracker   *stats.Tracker
	Procs     *procinfo.Resolver
	ProcMon   *procmon.Monitor
	Sys       *sysstat.Monitor
	Bandwidth *bandwidth.Meter
	Dialer    *upstream.Dialer
	Proxy     *proxy.Engine
	DNS       *dnsfwd.Forwarder
	VPN       *vpn.Manager
	Caido     *caido.Manager
	Icpt      *intercept.Engine
	Tags      *tags.Manager
	Geo       *geo.Cache
	FW        *firewall.Engine
	VPNRot    *VPNRotator
	NF        *netfilter.Manager
	Started   time.Time
	RunDir    string
	VPNDir    string

	mu       sync.Mutex
	nfActive bool
	nfSig    string
	warnings []string
	level    int
}

var levels = map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3}

// New constructs the daemon from configuration (nothing is started yet).
func New(store *config.Store, runDir string) *Daemon {
	cfg := store.Get()
	d := &Daemon{Store: store, Started: time.Now(), RunDir: runDir, VPNDir: filepath.Join(filepath.Dir(store.Path()), "vpn")}
	d.level = levels[strings.ToLower(cfg.LogLevel)]
	d.Tracker = stats.New(cfg.MaxConnLog)
	d.Procs = procinfo.New()
	d.ProcMon = procmon.New()
	d.Sys = sysstat.New()
	{
		dataDir := "/var/lib/cyberboba"
		if sd := cfg.Intercept.SessionDir; sd != "" {
			dataDir = filepath.Dir(sd)
		}
		d.Bandwidth = bandwidth.New(filepath.Join(dataDir, "bandwidth.json"))
		d.Bandwidth.SetAlert(func(al bandwidth.Alert) {
			d.Tracker.Publish(stats.Event{Type: "bw_alert", Data: al})
			d.Logf("warn", "bandwidth: %s %s %.0f KB/s (%.0fx baseline, %d conns)",
				al.App, al.Kind, al.Rate/1024, al.Factor, al.Conns)
		})
		d.Bandwidth.ConfigureAlerts(cfg.Bandwidth.Alerts)
	}
	d.Tags = tags.New()
	d.Geo = geo.New(cfg.Geo.Enabled, cfg.Geo.Provider, cfg.Geo.CacheTTLHours, nil, func(f string, a ...interface{}) { d.Logf("warn", f, a...) })
	d.VPN = vpn.New(cfg, runDir, d.Logf, func(s vpn.Status) {
		d.Tracker.Publish(stats.Event{Type: "vpn", Data: s})
		if s.State == vpn.StateUp || s.State == vpn.StateDown {
			d.applyTagUDP(d.Store.Get())
		}
	})
	d.VPNRot = NewVPNRotator(d.VPN, d.Logf, func(group, member string) {
		d.Tracker.Publish(stats.Event{Type: "rotate", Data: map[string]string{"group": group, "member": member, "kind": "vpn"}})
	})
	// marker resolves a VPN-rotation name to its current member before marking.
	marker := func(name string) (uint32, bool, error) {
		if m, ok := d.VPNRot.Current(name); ok {
			name = m
		}
		return d.VPN.MarkFor(name)
	}
	d.Dialer = upstream.New(cfg, marker, func(s string) { d.Logf("warn", "%s", s) })
	d.Caido = caido.New(cfg.Caido, filepath.Join(filepath.Dir(store.Path()), "caido"), d.Logf,
		func(s caido.Status) { d.Tracker.Publish(stats.Event{Type: "caido", Data: s}) })
	d.applyCaidoProxy(cfg)
	// The DNS router calls d.Proxy lazily, so construction order is safe.
	d.DNS = dnsfwd.New(cfg, d.Dialer, d.dnsRouter(cfg), d.Logf)
	{
		dataDir := "/var/lib/cyberboba"
		if sd := cfg.Intercept.SessionDir; sd != "" {
			dataDir = filepath.Dir(sd)
		}
		flt := dnsfwd.NewFilter(filepath.Join(dataDir, "dns-blocklists.cache"), d.Logf)
		flt.Configure(cfg.DNSFilter)
		d.DNS.SetFilter(flt)
	}
	d.Proxy = proxy.New(cfg, d.Dialer, d.Procs, d.Tracker, d.DNS.Lookup, d.Logf)
	d.FW = firewall.New(cfg.Firewall,
		func(t string, data interface{}) { d.Tracker.Publish(stats.Event{Type: t, Data: data}) },
		func(fn func(*config.Firewall)) {
			_ = d.Store.Mutate(func(c *config.Config) error { fn(&c.Firewall); return nil })
		},
		func() bool { return d.Tracker.Subscribers() > 0 },
		d.Logf)
	d.Proxy.SetFirewall(d.FW)
	if ic, err := intercept.New(cfg.Intercept, d.Dialer, func(ev intercept.Event) {
		d.Tracker.Publish(stats.Event{Type: ev.Type, Data: ev.Data})
	}, d.Logf); err != nil {
		d.Warn("intercept engine disabled: " + err.Error())
	} else {
		d.Icpt = ic
		ic.ClientLookup = func(src, dst netip.AddrPort) (string, int) {
			if p, _, err := d.Procs.Lookup(src, dst); err == nil {
				return p.Name, p.PID
			}
			return "", 0
		}
		d.Proxy.SetInterceptor(interceptAdapter{ic})
	}
	store.Subscribe(d.onConfig)
	return d
}

func (d *Daemon) dnsRouter(cfg *config.Config) dnsfwd.Router {
	if !cfg.Proxifier.DNSViaRules {
		return nil
	}
	up := netip.Addr{}
	if ap, err := netip.ParseAddrPort(cfg.Proxifier.DNSUpstream); err == nil {
		up = ap.Addr()
	}
	return dnsfwd.RouterFromRules(func(c rules.Conn) rules.Decision { return d.Proxy.Evaluate(c) }, up)
}

func (d *Daemon) applyCaidoProxy(cfg *config.Config) {
	if cfg.Caido.Enabled {
		d.Dialer.SetExtraProxy(d.Caido.ProxyEntry())
	} else {
		d.Dialer.RemoveExtraProxy(d.Caido.ProxyEntry().Name)
	}
}

// interceptAdapter bridges the proxy engine to the interceptor.
type interceptAdapter struct{ e *intercept.Engine }

func (a interceptAdapter) HandleConn(c net.Conn, head []byte, host string, ip netip.Addr, port int, app string, pid int) {
	a.e.HandleConn(c, head, host, ip, port, intercept.Meta{App: app, PID: pid, Source: "transparent"})
}

// Logf is the daemon logger: stderr + in-memory ring + SSE.
func (d *Daemon) Logf(level, format string, args ...interface{}) {
	if levels[level] < d.level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", level, msg)
	d.Tracker.Log(level, msg)
}

// Warn records a persistent warning shown in the UI.
func (d *Daemon) Warn(msg string) {
	d.mu.Lock()
	d.warnings = append(d.warnings, msg)
	d.mu.Unlock()
	d.Logf("warn", "%s", msg)
}

// Warnings returns persistent warnings.
func (d *Daemon) Warnings() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.warnings...)
}

// Start brings up listeners, netfilter, autostart VPNs and Caido.
func (d *Daemon) Start() error {
	cfg := d.Store.Get()
	if err := os.MkdirAll(d.RunDir, 0o755); err != nil {
		return err
	}
	if err := d.Proxy.Start(cfg.Proxifier.ListenTCP, cfg.Proxifier.IPv6); err != nil {
		return fmt.Errorf("proxy listener: %w", err)
	}
	if cfg.Proxifier.ListenSOCKS != "" {
		if err := d.Proxy.StartSOCKS(cfg.Proxifier.ListenSOCKS); err != nil {
			d.Warn("socks listener: " + err.Error())
		}
	}
	if cfg.Proxifier.ListenHTTP != "" {
		if err := d.Proxy.StartHTTP(cfg.Proxifier.ListenHTTP); err != nil {
			d.Warn("http listener: " + err.Error())
		}
	}
	if err := d.DNS.Start(cfg.Proxifier.ListenDNS, cfg.Proxifier.IPv6); err != nil {
		d.Warn("dns forwarder: " + err.Error())
	}
	if d.Icpt != nil && cfg.Intercept.Enabled && cfg.Intercept.Listen != "" {
		if err := d.Icpt.Start(cfg.Intercept.Listen); err != nil {
			d.Warn("intercept listener: " + err.Error())
		}
	}
	go d.ticker()
	go d.netfilterWatchdog()
	go d.vpnWatchdog()
	go d.rotateWatchdog()
	if err := netfilter.Available(); err != nil {
		d.Warn("transparent proxying disabled: " + err.Error())
	} else if cfg.Proxifier.Enabled {
		defer d.applyStealth(cfg)
		if err := d.EnableNetfilter(); err != nil {
			d.Warn("netfilter: " + err.Error())
		} else {
			d.applyTagUDP(cfg)
		}
	}
	if cfg.Caido.Enabled && cfg.Caido.Managed {
		if err := d.Caido.Start(); err != nil {
			d.Warn("caido: " + err.Error())
		}
	}
	go d.VPN.Autostart()
	go d.VPNRot.SetConfig(d.Store.Get().VPNRotations)
	d.Logf("info", "CyberBoba Security Suite %s started (proxy %s, dns %s)", Version, cfg.Proxifier.ListenTCP, cfg.Proxifier.ListenDNS)
	return nil
}

// Stop tears everything down.
func (d *Daemon) Stop() {
	d.Logf("info", "shutting down")
	_ = d.DisableNetfilter()
	d.Proxy.Stop()
	d.DNS.Stop()
	if d.Icpt != nil {
		d.Icpt.Stop()
	}
	netfilter.ClearTagUDP()
	if d.Tags != nil {
		d.Tags.Cleanup()
	}
	if d.VPNRot != nil {
		d.VPNRot.Stop()
	}
	if d.Bandwidth != nil {
		d.Bandwidth.Flush()
	}
	d.VPN.DownAll()
	_ = d.Caido.Stop()
}

func (d *Daemon) ticker() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		d.Tracker.Tick()
		if d.Bandwidth != nil {
			d.Bandwidth.Sample(d.Tracker.List(0, true))
		}
	}
}

// netfilterWatchdog re-asserts rule order every few seconds (wg-quick and
// friends insert their own rules at the top of chains).
func (d *Daemon) netfilterWatchdog() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		d.mu.Lock()
		nf := d.NF
		d.mu.Unlock()
		if nf == nil {
			continue
		}
		if err := nf.EnsureOrder(); err != nil {
			d.Logf("warn", "netfilter order: %v", err)
		}
	}
}

// vpnWatchdog refreshes tunnel status so that lost interfaces trigger the
// kill switch / reconnect logic even when no client is polling.
func (d *Daemon) vpnWatchdog() {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for range t.C {
		d.VPN.All()
	}
}

// rotateWatchdog advances proxy/VPN rotation groups on schedule and publishes
// a "rotate" event so the UI reflects the active member live.
func (d *Daemon) rotateWatchdog() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		for _, ch := range d.Dialer.TickRotations() {
			d.Logf("info", "proxy rotation %q -> %s", ch.Group, ch.Member)
			d.Tracker.Publish(stats.Event{Type: "rotate", Data: ch})
		}
		if d.VPNRot != nil {
			d.VPNRot.Tick()
		}
	}
}

func (d *Daemon) nfOptions(cfg *config.Config) netfilter.Options {
	_, tp, _ := net.SplitHostPort(cfg.Proxifier.ListenTCP)
	_, dp, _ := net.SplitHostPort(cfg.Proxifier.ListenDNS)
	var tcpPort, dnsPort int
	fmt.Sscanf(tp, "%d", &tcpPort)
	fmt.Sscanf(dp, "%d", &dnsPort)
	return netfilter.Options{MarkBase: cfg.BypassMark(), TCPPort: tcpPort, DNSPort: dnsPort,
		BlockQUIC: cfg.Proxifier.BlockQUIC, IPv6: cfg.Proxifier.IPv6,
		Logf: func(f string, a ...interface{}) { d.Logf("warn", f, a...) }}
}

// EnableNetfilter installs the redirect rules.
func (d *Daemon) EnableNetfilter() error {
	if err := netfilter.Available(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.NF != nil {
		_ = d.NF.Uninstall()
	}
	d.NF = netfilter.New(d.nfOptions(d.Store.Get()))
	if err := d.NF.Install(); err != nil {
		_ = d.NF.Uninstall()
		d.NF = nil
		return err
	}
	d.nfActive = true
	d.nfSig = d.nfSignature(d.Store.Get())
	d.Logf("info", "netfilter rules installed")
	return nil
}

// nfSignature captures the netfilter-relevant config so onConfig can skip a
// costly (and briefly disruptive) reinstall when only unrelated settings (e.g.
// firewall programs) changed.
func (d *Daemon) nfSignature(cfg *config.Config) string {
	o := d.nfOptions(cfg)
	return fmt.Sprintf("%d|%d|%d|%v|%v", o.MarkBase, o.TCPPort, o.DNSPort, o.BlockQUIC, o.IPv6)
}

// applyTagUDP builds the per-tag UDP policy from rules whose apps are solely
// tag references and whose action is vpn or block.
func (d *Daemon) applyTagUDP(cfg *config.Config) {
	if !d.NetfilterActive() || d.Tags == nil || !d.Tags.Available() {
		return
	}
	var specs []netfilter.TagUDPSpec
	for _, r := range cfg.Rules {
		if !r.IsEnabled() || len(r.Apps) == 0 {
			continue
		}
		tag := soleTag(r.Apps)
		if tag == "" {
			continue
		}
		switch r.Action {
		case config.ActionBlock:
			cid, _, err := d.Tags.ClassID(tag)
			if err != nil {
				continue
			}
			specs = append(specs, netfilter.TagUDPSpec{Tag: tag, ClassID: cid, Block: true})
			d.Tags.SetUDPAction(tag, "block")
		case config.ActionVPN:
			idx := cfg.VPNIndex(r.VPN)
			if idx < 0 {
				continue
			}
			mark, ok, err := d.VPN.MarkFor(r.VPN)
			if err != nil || !ok {
				continue // full-mode or down VPN: default route already covers UDP
			}
			cid, _, err := d.Tags.ClassID(tag)
			if err != nil {
				continue
			}
			specs = append(specs, netfilter.TagUDPSpec{Tag: tag, ClassID: cid, Mark: mark})
			d.Tags.SetUDPAction(tag, "vpn:"+r.VPN)
		}
	}
	if err := netfilter.ApplyTagUDP(specs); err != nil {
		d.Logf("warn", "tag udp policy: %v", err)
	}
}

// ReapplyTagUDP re-applies the per-tag UDP policy (after a tag is attached).
func (d *Daemon) ReapplyTagUDP() { d.applyTagUDP(d.Store.Get()) }

// soleTag returns the tag name if apps consists only of tag: entries that
// share one tag, else "".
func soleTag(apps []string) string {
	tag := ""
	for _, a := range apps {
		if !strings.HasPrefix(a, "tag:") {
			return ""
		}
		name := strings.TrimPrefix(a, "tag:")
		if tag == "" {
			tag = name
		} else if tag != name {
			return ""
		}
	}
	return tag
}

// applyStealth turns the inbound stealth firewall on/off to match config.
// It is a no-op when netfilter is not active (needs root).
func (d *Daemon) applyStealth(cfg *config.Config) {
	if !d.NetfilterActive() {
		return
	}
	if cfg.Firewall.Enabled && cfg.Firewall.Stealth {
		if err := netfilter.StealthOn(cfg.Firewall.AllowLANInbound); err != nil {
			d.Logf("error", "stealth on: %v", err)
		} else {
			d.Logf("info", "firewall stealth enabled (inbound silently dropped)")
		}
	} else {
		_ = netfilter.StealthOff()
	}
}

// EnableNetfilterAndTags enables interception and applies tag UDP policy.
func (d *Daemon) EnableNetfilterAndTags() error {
	if err := d.EnableNetfilter(); err != nil {
		return err
	}
	cfg := d.Store.Get()
	d.applyTagUDP(cfg)
	d.applyStealth(cfg)
	return nil
}

// DisableNetfilter removes them.
func (d *Daemon) DisableNetfilter() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.NF == nil {
		return nil
	}
	_ = netfilter.StealthOff()
	err := d.NF.Uninstall()
	netfilter.ClearTagUDP()
	d.NF = nil
	d.nfActive = false
	d.Logf("info", "netfilter rules removed")
	return err
}

// NetfilterActive reports whether interception is on.
func (d *Daemon) NetfilterActive() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.nfActive
}

// onConfig applies a new configuration live.
func (d *Daemon) onConfig(cfg *config.Config) {
	d.level = levels[strings.ToLower(cfg.LogLevel)]
	d.Dialer.SetConfig(cfg)
	d.Proxy.SetConfig(cfg)
	d.DNS.SetConfig(cfg)
	if flt := d.DNS.Filter(); flt != nil {
		flt.Configure(cfg.DNSFilter)
	}
	d.VPN.SetConfig(cfg)
	if d.Icpt != nil {
		d.Icpt.SetConfig(cfg.Intercept)
	}
	if d.Bandwidth != nil {
		d.Bandwidth.ConfigureAlerts(cfg.Bandwidth.Alerts)
	}
	d.Geo.Configure(cfg.Geo.Enabled, cfg.Geo.Provider, cfg.Geo.CacheTTLHours)
	if d.FW != nil {
		d.FW.SetConfig(cfg.Firewall)
	}
	if d.VPNRot != nil {
		d.VPNRot.SetConfig(cfg.VPNRotations)
	}
	d.applyStealth(cfg)
	old := d.Caido.Config()
	d.Caido.SetConfig(cfg.Caido)
	d.applyCaidoProxy(cfg)
	if old.Enabled != cfg.Caido.Enabled || old.Managed != cfg.Caido.Managed || old.Listen != cfg.Caido.Listen ||
		old.Binary != cfg.Caido.Binary || old.DataPath != cfg.Caido.DataPath {
		if cfg.Caido.Enabled && cfg.Caido.Managed {
			if err := d.Caido.Restart(); err != nil {
				d.Logf("error", "caido restart: %v", err)
			}
		} else {
			_ = d.Caido.Stop()
		}
	}
	// Re-install netfilter only if its parameters actually changed (avoid
	// tearing down the redirect on every firewall/program edit).
	if d.NetfilterActive() && d.nfSignature(cfg) != d.nfSig {
		if err := d.EnableNetfilter(); err != nil {
			d.Logf("error", "netfilter reinstall: %v", err)
		}
	}
	d.applyTagUDP(cfg)
	d.Logf("info", "configuration applied")
}

// Check is one doctor result.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Doctor runs environment checks.
func (d *Daemon) Doctor() []Check {
	var out []Check
	add := func(name string, ok bool, detail string) { out = append(out, Check{name, ok, detail}) }
	add("root", os.Geteuid() == 0, fmt.Sprintf("euid=%d", os.Geteuid()))
	for _, bin := range []string{"iptables", "ip6tables", "ip", "wg", "wg-quick", "openvpn", "certutil", "update-ca-certificates"} {
		p, err := lookPath(bin)
		add(bin, err == nil, p)
	}
	_, err := os.Stat("/dev/net/tun")
	add("/dev/net/tun", err == nil, "")
	add("netfilter", d.NetfilterActive(), "transparent interception active")
	cs := d.Caido.Status()
	add("caido-cli", cs.Version != "", cs.Binary+" "+cs.Version)
	add("caido reachable", cs.Reachable, cs.Listen)
	rc, _ := os.ReadFile("/etc/resolv.conf")
	add("resolv.conf", true, strings.TrimSpace(strings.Join(grepLines(string(rc), "nameserver"), ", ")))
	return out
}

func grepLines(s, sub string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), sub) {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

func lookPath(bin string) (string, error) {
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin"} {
		p := filepath.Join(dir, bin)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", os.ErrNotExist
}
