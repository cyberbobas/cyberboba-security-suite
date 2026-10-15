// Package vpn manages WireGuard (via wg-quick) and OpenVPN tunnels and the
// policy routing needed for "selective" profiles.
package vpn

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyberboba/internal/config"
	"cyberboba/internal/netfilter"
)

// State of a tunnel.
type State string

const (
	StateDown       State = "down"
	StateConnecting State = "connecting"
	StateUp         State = "up"
	StateError      State = "error"
)

// Status is the JSON view of a tunnel.
type Status struct {
	Name          string         `json:"name"`
	Type          config.VPNType `json:"type"`
	Mode          config.VPNMode `json:"mode"`
	State         State          `json:"state"`
	Interface     string         `json:"interface"`
	Since         *time.Time     `json:"since"`
	RxBytes       int64          `json:"rx_bytes"`
	TxBytes       int64          `json:"tx_bytes"`
	Endpoint      string         `json:"endpoint"`
	LastHandshake *time.Time     `json:"last_handshake"`
	LocalIP       string         `json:"local_ip"`
	PID           int            `json:"pid,omitempty"`
	Error         string         `json:"error"`
	Mark          uint32         `json:"mark,omitempty"`
	Table         int            `json:"table,omitempty"`
	KillSwitch    bool           `json:"kill_switch_active"`
	Reconnects    int            `json:"reconnects"`
	// External is set when the interface exists but was brought up outside
	// cyberboba (wg-quick by hand, a tray helper, NetworkManager). The tunnel
	// is shown as up and can be taken down from here.
	External bool `json:"external"`
}

// backend is implemented by the WireGuard and OpenVPN drivers.
type backend interface {
	Up() error
	Down() error
	Refresh(*Status)
	Log() []string
}

type tunnel struct {
	mu       sync.Mutex
	profile  config.VPN
	status   Status
	be       backend
	routed   bool
	wantUp   bool // user asked for the tunnel to be up (reconnect / kill switch)
	endpoint string
}

// Manager owns all tunnels.
type Manager struct {
	mu      sync.Mutex
	cfg     *config.Config
	tunnels map[string]*tunnel
	logf    func(level, format string, args ...interface{})
	publish func(Status)
	RunDir  string // runtime files (generated wg configs)
	dryRun  bool
}

// New creates a Manager.
func New(cfg *config.Config, runDir string, logf func(level, format string, args ...interface{}), publish func(Status)) *Manager {
	if logf == nil {
		logf = func(string, string, ...interface{}) {}
	}
	if publish == nil {
		publish = func(Status) {}
	}
	m := &Manager{cfg: cfg, tunnels: map[string]*tunnel{}, logf: logf, publish: publish, RunDir: runDir}
	m.SetConfig(cfg)
	return m
}

var ifaceRe = regexp.MustCompile(`[^a-zA-Z0-9_.-]`)

// InterfaceName derives the kernel interface name for a profile.
func InterfaceName(p config.VPN) string {
	n := p.Interface
	if n == "" {
		if p.Type == config.VPNWireGuard {
			n = strings.TrimSuffix(filepath.Base(p.Config), ".conf")
		} else {
			n = "tr-" + p.Name
		}
	}
	n = ifaceRe.ReplaceAllString(n, "")
	if len(n) > 15 {
		n = n[:15]
	}
	return n
}

// SetConfig reconciles profiles with the configuration: removed profiles
// are brought down, changed ones keep running until restarted.
func (m *Manager) SetConfig(cfg *config.Config) {
	m.mu.Lock()
	m.cfg = cfg
	for name, t := range m.tunnels {
		if cfg.VPNByName(name) == nil {
			m.mu.Unlock()
			_ = m.Down(name)
			m.mu.Lock()
			delete(m.tunnels, name)
		}
		_ = t
	}
	for i := range cfg.VPNs {
		p := cfg.VPNs[i]
		t, ok := m.tunnels[p.Name]
		if !ok {
			t = &tunnel{profile: p}
			t.status = Status{Name: p.Name, Type: p.Type, Mode: p.Mode, State: StateDown, Interface: InterfaceName(p)}
			t.be = m.newBackend(t)
			m.tunnels[p.Name] = t
		} else {
			t.mu.Lock()
			t.profile = p
			t.status.Type, t.status.Mode = p.Type, p.Mode
			t.mu.Unlock()
		}
	}
	m.mu.Unlock()
}

func (m *Manager) newBackend(t *tunnel) backend {
	switch t.profile.Type {
	case config.VPNWireGuard:
		return &wireguard{m: m, t: t}
	case config.VPNOpenVPN:
		return &openvpn{m: m, t: t}
	}
	return nil
}

func interfaceExists(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}

func (m *Manager) get(name string) (*tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[name]
	if !ok {
		return nil, fmt.Errorf("unknown vpn %q", name)
	}
	return t, nil
}

func (m *Manager) markTable(name string) (mark uint32, table int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := m.cfg.VPNIndex(name)
	if idx < 0 {
		return 0, 0
	}
	return m.cfg.VPNMark(idx), m.cfg.VPNTable(idx)
}

// Up starts a tunnel.
func (m *Manager) Up(name string) error {
	t, err := m.get(name)
	if err != nil {
		return err
	}
	t.mu.Lock()
	if t.status.State == StateConnecting {
		t.mu.Unlock()
		return nil
	}
	// An interface brought up by NetworkManager is marked External. Treat it
	// as "not ours" and take over instead of returning success with a tunnel
	// we do not control.
	if t.status.State == StateUp && !t.status.External && interfaceExists(t.status.Interface) {
		t.wantUp = true
		t.mu.Unlock()
		return nil
	}
	t.status.State = StateConnecting
	t.status.Error = ""
	t.status.External = false
	t.wantUp = true
	t.mu.Unlock()
	m.publish(t.snapshot())
	if err := t.be.Up(); err != nil {
		t.mu.Lock()
		t.wantUp = false
		t.mu.Unlock()
		t.mu.Lock()
		t.status.State = StateError
		t.status.Error = err.Error()
		t.mu.Unlock()
		m.publish(t.snapshot())
		return err
	}
	return nil
}

// Down stops a tunnel.
func (m *Manager) Down(name string) error {
	t, err := m.get(name)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.wantUp = false
	t.mu.Unlock()
	err = t.be.Down()
	m.unroute(t)
	// Always clear the kill switch on an explicit down, even if the status
	// flag is stale (e.g. a partial failure while arming it).
	_ = netfilter.KillSwitchOff(t.profile.Name)
	t.mu.Lock()
	t.status.KillSwitch = false
	t.mu.Unlock()
	t.mu.Lock()
	t.status.State = StateDown
	t.status.Since = nil
	t.status.PID = 0
	if err != nil {
		t.status.Error = err.Error()
	}
	t.mu.Unlock()
	m.publish(t.snapshot())
	return err
}

// DownAll stops every tunnel the daemon started.
func (m *Manager) DownAll() {
	m.mu.Lock()
	names := make([]string, 0, len(m.tunnels))
	for n := range m.tunnels {
		names = append(names, n)
	}
	m.mu.Unlock()
	for _, n := range names {
		if s, _ := m.Status(n); s.State == StateUp || s.State == StateConnecting {
			_ = m.Down(n)
		}
	}
}

// Autostart brings up profiles flagged autostart.
func (m *Manager) Autostart() {
	m.mu.Lock()
	var names []string
	for _, p := range m.cfg.VPNs {
		if p.Autostart {
			names = append(names, p.Name)
		}
	}
	m.mu.Unlock()
	for _, n := range names {
		if err := m.Up(n); err != nil {
			m.logf("error", "vpn %s autostart: %v", n, err)
		}
	}
}

// Status returns the live status of one tunnel.
func (m *Manager) Status(name string) (Status, error) {
	t, err := m.get(name)
	if err != nil {
		return Status{}, err
	}
	t.be.Refresh(&t.status)
	return t.snapshot(), nil
}

// All returns statuses in config order.
func (m *Manager) All() []Status {
	m.mu.Lock()
	var ts []*tunnel
	for _, p := range m.cfg.VPNs {
		if t, ok := m.tunnels[p.Name]; ok {
			ts = append(ts, t)
		}
	}
	m.mu.Unlock()
	out := make([]Status, 0, len(ts))
	for _, t := range ts {
		t.mu.Lock()
		before := t.status.State
		t.be.Refresh(&t.status)
		s := t.status
		t.mu.Unlock()
		if s.State != before {
			m.publish(s)
		}
		out = append(out, s)
	}
	return out
}

// cleanupWgQuickRules removes the policy-routing rules a full-tunnel wg-quick
// leaves behind when its interface is deleted with a `Table = off` config (or
// by `ip link del`): "not fwmark X lookup X" and "main suppress_prefixlength 0".
// Stale rules are harmless on their own but confuse later `wg-quick up`
// runs and every diagnosis of "why does my traffic go nowhere".
func cleanupWgQuickRules(table string) {
	if table == "" {
		return
	}
	for _, fam := range []string{"-4", "-6"} {
		for i := 0; i < 20; i++ {
			out, _ := exec.Command("ip", fam, "rule", "show").Output()
			if !strings.Contains(string(out), "lookup "+table) {
				break
			}
			if err := exec.Command("ip", fam, "rule", "delete", "table", table).Run(); err != nil {
				break
			}
		}
		for i := 0; i < 20; i++ {
			out, _ := exec.Command("ip", fam, "rule", "show").Output()
			if !strings.Contains(string(out), "suppress_prefixlength 0") {
				break
			}
			if err := exec.Command("ip", fam, "rule", "delete", "table", "main", "suppress_prefixlength", "0").Run(); err != nil {
				break
			}
		}
	}
}

// wgFwmarkTable returns the decimal routing table a running wg-quick full
// tunnel uses (its fwmark), or "" when the interface has no fwmark.
func wgFwmarkTable(iface string) string {
	out, err := exec.Command("wg", "show", iface, "fwmark").Output()
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if !strings.HasPrefix(v, "0x") {
		return ""
	}
	n, err := strconv.ParseUint(v[2:], 16, 32)
	if err != nil || n == 0 {
		return ""
	}
	return strconv.FormatUint(n, 10)
}

// Log returns backend output.
func (m *Manager) Log(name string) ([]string, error) {
	t, err := m.get(name)
	if err != nil {
		return nil, err
	}
	return t.be.Log(), nil
}

// MarkFor implements upstream.VPNMarker.
func (m *Manager) MarkFor(name string) (uint32, bool, error) {
	t, err := m.get(name)
	if err != nil {
		return 0, false, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status.State != StateUp {
		return 0, false, fmt.Errorf("vpn %q is %s", name, t.status.State)
	}
	if t.profile.Mode != config.VPNModeSelective {
		return 0, false, nil
	}
	return t.status.Mark, true, nil
}

func (t *tunnel) snapshot() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

// route installs the policy routing table for a selective tunnel.
func (m *Manager) route(t *tunnel, iface, gw4, gw6 string) error {
	mark, table := m.markTable(t.profile.Name)
	t.mu.Lock()
	t.status.Mark, t.status.Table = mark, table
	selective := t.profile.Mode == config.VPNModeSelective
	t.mu.Unlock()
	if !selective {
		return nil
	}
	if err := netfilter.AddRouteTable(netfilter.RouteTable{Table: table, Mark: mark, Iface: iface, Gateway: gw4}); err != nil {
		return err
	}
	if err := netfilter.AddRouteTable(netfilter.RouteTable{Table: table, Mark: mark, Iface: iface, Gateway: gw6, V6: true}); err != nil {
		m.logf("debug", "vpn %s: no ipv6 table: %v", t.profile.Name, err)
	}
	t.mu.Lock()
	t.routed = true
	t.mu.Unlock()
	return nil
}

func (m *Manager) unroute(t *tunnel) {
	t.mu.Lock()
	routed := t.routed
	mark, table := t.status.Mark, t.status.Table
	t.routed = false
	t.mu.Unlock()
	if !routed {
		return
	}
	netfilter.DelRouteTable(netfilter.RouteTable{Table: table, Mark: mark})
	netfilter.DelRouteTable(netfilter.RouteTable{Table: table, Mark: mark, V6: true})
}

// killSwitch arms or disarms the outbound block for a tunnel.
func (m *Manager) killSwitch(t *tunnel, on bool) {
	t.mu.Lock()
	ks := t.profile.KillSwitch
	cur := t.status.KillSwitch
	ep := t.endpoint
	name := t.profile.Name
	t.mu.Unlock()
	if !ks && !on && !cur {
		return
	}
	if on == cur {
		return
	}
	var err error
	if on {
		err = netfilter.KillSwitchOn(name, ep)
	} else {
		err = netfilter.KillSwitchOff(name)
	}
	if err != nil {
		m.logf("error", "vpn %s: kill switch: %v", name, err)
		return
	}
	t.mu.Lock()
	t.status.KillSwitch = on
	t.mu.Unlock()
	m.logf("info", "vpn %s: kill switch %v", name, on)
	m.publish(t.snapshot())
}

// lost is called by backends when an established tunnel goes away
// unexpectedly: arms the kill switch and schedules a reconnect.
func (m *Manager) lost(t *tunnel, err error) {
	t.mu.Lock()
	want := t.wantUp
	ks := t.profile.KillSwitch
	rc := t.profile.Reconnect
	name := t.profile.Name
	t.mu.Unlock()
	if !want {
		return
	}
	if ks {
		m.killSwitch(t, true)
	}
	if !rc {
		return
	}
	go func() {
		for attempt := 1; ; attempt++ {
			delay := time.Duration(attempt) * 2 * time.Second
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
			time.Sleep(delay)
			t.mu.Lock()
			want := t.wantUp
			st := t.status.State
			t.mu.Unlock()
			if !want || st == StateUp || st == StateConnecting {
				return
			}
			m.logf("info", "vpn %s: reconnect attempt %d", name, attempt)
			t.mu.Lock()
			t.status.State = StateConnecting
			t.status.Reconnects++
			t.mu.Unlock()
			m.publish(t.snapshot())
			if err := t.be.Up(); err == nil {
				return
			} else {
				m.markError(t, err)
			}
		}
	}()
}

func (m *Manager) markUp(t *tunnel, iface string) {
	m.killSwitch(t, false)
	now := time.Now()
	t.mu.Lock()
	t.status.State = StateUp
	t.status.Since = &now
	t.status.Error = ""
	if iface != "" {
		t.status.Interface = iface
	}
	t.mu.Unlock()
	m.publish(t.snapshot())
}

func (m *Manager) markError(t *tunnel, err error) {
	t.mu.Lock()
	t.status.State = StateError
	t.status.Error = err.Error()
	t.status.Since = nil
	t.mu.Unlock()
	m.publish(t.snapshot())
}

// authFile returns the path of the OpenVPN credentials file for a profile,
// writing username/password from the config when present.
func (m *Manager) authFile(p config.VPN) (string, error) {
	if p.Username == "" {
		return p.AuthFile, nil
	}
	dir := filepath.Join(m.RunDir, "auth")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, ifaceRe.ReplaceAllString(p.Name, "")+".auth")
	if err := os.WriteFile(path, []byte(p.Username+"\n"+p.Password+"\n"), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// Import stores a config file and returns the path.
func (m *Manager) Import(dir, name string, typ config.VPNType, content string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	base := ifaceRe.ReplaceAllString(name, "")
	if base == "" {
		return "", errors.New("invalid name")
	}
	ext := ".conf"
	if typ == config.VPNOpenVPN {
		ext = ".ovpn"
	}
	path := filepath.Join(dir, base+ext)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// --- helpers shared by backends ---

func localIPv4(iface string) string {
	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", iface).Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	for i, s := range f {
		if s == "inet" && i+1 < len(f) {
			return strings.SplitN(f[i+1], "/", 2)[0]
		}
	}
	return ""
}

func ifaceCounters(iface string) (rx, tx int64) {
	read := func(p string) int64 {
		b, err := os.ReadFile(p)
		if err != nil {
			return 0
		}
		var n int64
		fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &n)
		return n
	}
	return read("/sys/class/net/" + iface + "/statistics/rx_bytes"), read("/sys/class/net/" + iface + "/statistics/tx_bytes")
}

// ringLog keeps the last N lines of a backend's output.
type ringLog struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func (r *ringLog) add(s string) {
	r.mu.Lock()
	if r.max == 0 {
		r.max = 500
	}
	r.lines = append(r.lines, s)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
	r.mu.Unlock()
}

func (r *ringLog) get() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}
