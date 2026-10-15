// Package netfilter installs and removes the iptables rules that steer
// locally generated traffic into the transparent proxy, plus the policy
// routing tables used by selective VPN profiles.
package netfilter

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const (
	chainNAT    = "CYBERBOBA_OUT"
	chainFilter = "CYBERBOBA_FILTER"
	chainRaw    = "CYBERBOBA_RAW"
)

// Options describe what to install.
type Options struct {
	MarkBase   uint32 // bypass mark; all marks in [MarkBase, MarkBase+255] are exempt
	TCPPort    int    // transparent TCP listener port
	DNSPort    int    // DNS forwarder port (0 = don't redirect DNS)
	BlockQUIC  bool
	IPv6       bool
	ExtraSkip  []string // destination CIDRs that are never redirected
	Logf       func(string, ...interface{})
	DryRun     bool
	CommandOut []string // DryRun: collected commands
}

// Manager owns the installed state.
type Manager struct {
	mu        sync.Mutex
	opts      Options
	installed bool
	hasV6     bool
}

// New creates a manager.
func New(o Options) *Manager {
	if o.Logf == nil {
		o.Logf = func(string, ...interface{}) {}
	}
	return &Manager{opts: o}
}

// Installed reports whether the rules are currently in place.
func (m *Manager) Installed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.installed
}

// Available reports whether iptables can be used (root + binary present).
func Available() error {
	if os.Geteuid() != 0 {
		return errors.New("not running as root")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return errors.New("iptables binary not found")
	}
	return nil
}

func (m *Manager) run(bin string, args ...string) error {
	if m.opts.DryRun {
		m.opts.CommandOut = append(m.opts.CommandOut, bin+" "+strings.Join(args, " "))
		return nil
	}
	out, err := exec.Command(bin, xt(args)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// exists runs a -C check.
func (m *Manager) exists(bin string, args ...string) bool {
	if m.opts.DryRun {
		return false
	}
	return exec.Command(bin, xt(args)...).Run() == nil
}

// xt prepends "-w 5" so concurrent iptables invocations (watchdog, VPN
// scripts, other tools) wait for the xtables lock instead of failing.
func xt(args []string) []string {
	return append([]string{"-w", "5"}, args...)
}

func (m *Manager) markMatch() string {
	return fmt.Sprintf("0x%x/0xffffff00", m.opts.MarkBase)
}

// Install (re)creates the chains. It is idempotent.
func (m *Manager) Install() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.installFamily("iptables", false); err != nil {
		return err
	}
	if m.opts.IPv6 {
		if err := m.installFamily("ip6tables", true); err != nil {
			m.opts.Logf("ipv6 netfilter disabled: %v", err)
			m.hasV6 = false
		} else {
			m.hasV6 = true
		}
	}
	m.installed = true
	return nil
}

func (m *Manager) installFamily(bin string, v6 bool) error {
	loopback := "127.0.0.0/8"
	rejectWith := "icmp-port-unreachable"
	if v6 {
		loopback = "::1/128"
		rejectWith = "icmp6-port-unreachable"
	}
	// NAT chain
	_ = m.run(bin, "-t", "nat", "-N", chainNAT)
	if err := m.run(bin, "-t", "nat", "-F", chainNAT); err != nil {
		return err
	}
	steps := [][]string{
		{"-t", "nat", "-A", chainNAT, "-m", "mark", "--mark", m.markMatch(), "-j", "RETURN"},
		{"-t", "nat", "-A", chainNAT, "-o", "lo", "-j", "RETURN"},
		{"-t", "nat", "-A", chainNAT, "-d", loopback, "-j", "RETURN"},
		{"-t", "nat", "-A", chainNAT, "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN"},
	}
	for _, cidr := range m.opts.ExtraSkip {
		if _, ipn, err := net.ParseCIDR(cidr); err == nil && (ipn.IP.To4() != nil) != v6 {
			steps = append(steps, []string{"-t", "nat", "-A", chainNAT, "-d", cidr, "-j", "RETURN"})
		}
	}
	if m.opts.DNSPort > 0 {
		steps = append(steps, []string{"-t", "nat", "-A", chainNAT, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(m.opts.DNSPort)})
		steps = append(steps, []string{"-t", "nat", "-A", chainNAT, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(m.opts.TCPPort)})
	}
	steps = append(steps, []string{"-t", "nat", "-A", chainNAT, "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", strconv.Itoa(m.opts.TCPPort)})
	for _, s := range steps {
		if err := m.run(bin, s...); err != nil {
			return err
		}
	}
	if !m.exists(bin, "-t", "nat", "-C", "OUTPUT", "-j", chainNAT) {
		if err := m.run(bin, "-t", "nat", "-I", "OUTPUT", "1", "-j", chainNAT); err != nil {
			return err
		}
	}
	// Filter chain (QUIC block)
	_ = m.run(bin, "-t", "filter", "-N", chainFilter)
	if err := m.run(bin, "-t", "filter", "-F", chainFilter); err != nil {
		return err
	}
	if m.opts.BlockQUIC {
		fs := [][]string{
			{"-t", "filter", "-A", chainFilter, "-m", "mark", "--mark", m.markMatch(), "-j", "RETURN"},
			{"-t", "filter", "-A", chainFilter, "-o", "lo", "-j", "RETURN"},
			{"-t", "filter", "-A", chainFilter, "-p", "udp", "--dport", "443", "-j", "REJECT", "--reject-with", rejectWith},
			{"-t", "filter", "-A", chainFilter, "-p", "udp", "--dport", "80", "-j", "REJECT", "--reject-with", rejectWith},
		}
		for _, s := range fs {
			if err := m.run(bin, s...); err != nil {
				return err
			}
		}
	}
	if !m.exists(bin, "-t", "filter", "-C", "OUTPUT", "-j", chainFilter) {
		if err := m.run(bin, "-t", "filter", "-I", "OUTPUT", "1", "-j", chainFilter); err != nil {
			return err
		}
	}
	// Raw chain: replies of REDIRECTed connections re-enter through lo with
	// a foreign source address (the original destination). Anti-spoofing
	// rules such as the one wg-quick installs for full tunnels
	// ("-d <tunnel ip> ! -i wg0 ! --src-type LOCAL -j DROP") would kill
	// them, so loopback packets leave the raw table before those rules.
	_ = m.run(bin, "-t", "raw", "-N", chainRaw)
	if err := m.run(bin, "-t", "raw", "-F", chainRaw); err != nil {
		return err
	}
	if err := m.run(bin, "-t", "raw", "-A", chainRaw, "-i", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	return m.ensureRawFirst(bin)
}

// ensureRawFirst keeps the jump to the raw chain as rule 1 of PREROUTING.
func (m *Manager) ensureRawFirst(bin string) error {
	if m.opts.DryRun {
		return m.run(bin, "-t", "raw", "-I", "PREROUTING", "1", "-j", chainRaw)
	}
	out, _ := exec.Command(bin, "-w", "5", "-t", "raw", "-S", "PREROUTING").Output()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	first := ""
	if len(lines) > 1 {
		first = lines[1]
	}
	if first == "-A PREROUTING -j "+chainRaw {
		return nil
	}
	for m.exists(bin, "-t", "raw", "-C", "PREROUTING", "-j", chainRaw) {
		if err := m.run(bin, "-t", "raw", "-D", "PREROUTING", "-j", chainRaw); err != nil {
			break
		}
	}
	return m.run(bin, "-t", "raw", "-I", "PREROUTING", "1", "-j", chainRaw)
}

// EnsureOrder re-asserts rule positions that other tools (wg-quick,
// openvpn scripts, firewalls) may have pushed down. Cheap; call periodically.
func (m *Manager) EnsureOrder() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.installed {
		return nil
	}
	var errs []string
	bins := []string{"iptables"}
	if m.hasV6 {
		bins = append(bins, "ip6tables")
	}
	for _, bin := range bins {
		if err := m.ensureRawFirst(bin); err != nil {
			errs = append(errs, err.Error())
		}
		if !m.exists(bin, "-t", "nat", "-C", "OUTPUT", "-j", chainNAT) {
			if err := m.run(bin, "-t", "nat", "-I", "OUTPUT", "1", "-j", chainNAT); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if !m.opts.DryRun {
		m.neutraliseWgQuickNft()
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// neutraliseWgQuickNft handles the nftables flavour of the wg-quick anti-spoof
// rule. On systems where wg-quick finds `nft` it does NOT use iptables; it
// creates its own table "wg-quick-<iface>" with a base chain
//
//	preraw { type filter hook prerouting priority -300; iifname != "wg0" ip daddr <tunnel ip> fib saddr type != local drop }
//
// Base chains of different tables are evaluated independently on the same hook,
// so an ACCEPT in our CYBERBOBA_RAW chain cannot protect loopback replies of
// REDIRECTed connections from that drop (only a verdict inside the same chain
// can). Insert `iifname "lo" accept` as rule 1 of every such preraw chain; the
// 5 s EnsureOrder watchdog re-applies it after any wg-quick up.
func (m *Manager) neutraliseWgQuickNft() {
	nft, err := exec.LookPath("nft")
	if err != nil {
		return
	}
	out, err := exec.Command(nft, "list", "tables").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line) // "table ip wg-quick-Mint"
		if len(f) != 3 || f[0] != "table" || !strings.HasPrefix(f[2], "wg-quick-") {
			continue
		}
		fam, table := f[1], f[2]
		chain, err := exec.Command(nft, "list", "chain", fam, table, "preraw").Output()
		if err != nil || strings.Contains(string(chain), "iifname \"lo\" accept") {
			continue
		}
		if err := exec.Command(nft, "insert", "rule", fam, table, "preraw", "iifname", "lo", "accept").Run(); err != nil {
			m.opts.Logf("netfilter: could not relax wg-quick nft anti-spoof rule in %s %s: %v", fam, table, err)
			continue
		}
		m.opts.Logf("netfilter: relaxed wg-quick nft anti-spoof rule in %s %s (loopback replies of redirected connections now pass)", fam, table)
	}
}

// Uninstall removes everything. Safe to call when nothing is installed.
func (m *Manager) Uninstall() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []string
	for _, bin := range []string{"iptables", "ip6tables"} {
		if bin == "ip6tables" && !m.opts.IPv6 {
			continue
		}
		if _, err := exec.LookPath(bin); err != nil && !m.opts.DryRun {
			continue
		}
		for m.exists(bin, "-t", "nat", "-C", "OUTPUT", "-j", chainNAT) {
			if err := m.run(bin, "-t", "nat", "-D", "OUTPUT", "-j", chainNAT); err != nil {
				errs = append(errs, err.Error())
				break
			}
		}
		for m.exists(bin, "-t", "filter", "-C", "OUTPUT", "-j", chainFilter) {
			if err := m.run(bin, "-t", "filter", "-D", "OUTPUT", "-j", chainFilter); err != nil {
				errs = append(errs, err.Error())
				break
			}
		}
		if m.opts.DryRun {
			m.run(bin, "-t", "nat", "-D", "OUTPUT", "-j", chainNAT)
			m.run(bin, "-t", "filter", "-D", "OUTPUT", "-j", chainFilter)
		}
		_ = m.run(bin, "-t", "nat", "-F", chainNAT)
		_ = m.run(bin, "-t", "nat", "-X", chainNAT)
		_ = m.run(bin, "-t", "filter", "-F", chainFilter)
		_ = m.run(bin, "-t", "filter", "-X", chainFilter)
		for m.exists(bin, "-t", "raw", "-C", "PREROUTING", "-j", chainRaw) {
			if m.run(bin, "-t", "raw", "-D", "PREROUTING", "-j", chainRaw) != nil {
				break
			}
		}
		if m.opts.DryRun {
			m.run(bin, "-t", "raw", "-D", "PREROUTING", "-j", chainRaw)
		}
		_ = m.run(bin, "-t", "raw", "-F", chainRaw)
		_ = m.run(bin, "-t", "raw", "-X", chainRaw)
	}
	m.installed = false
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Commands returns the commands recorded in DryRun mode.
func (m *Manager) Commands() []string { return m.opts.CommandOut }

// --- policy routing for selective VPNs ---

// RouteTable describes a per-VPN routing table.
type RouteTable struct {
	Table int
	Mark  uint32
	Iface string
	// Gateway is optional (OpenVPN tun with topology subnet needs none).
	Gateway string
	V6      bool
}

func ipBin(v6 bool) []string {
	if v6 {
		return []string{"ip", "-6"}
	}
	return []string{"ip", "-4"}
}

// AddRouteTable creates `default dev IFACE table N` and `rule fwmark MARK lookup N`.
func AddRouteTable(rt RouteTable) error {
	args := append(ipBin(rt.V6), "route", "replace", "default")
	if rt.Gateway != "" {
		args = append(args, "via", rt.Gateway)
	}
	args = append(args, "dev", rt.Iface, "table", strconv.Itoa(rt.Table))
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	// Make loopback/local reachable from the table too.
	_ = exec.Command(args[0], append(ipBin(rt.V6)[1:], "route", "add", "local", "default", "dev", "lo", "table", strconv.Itoa(rt.Table))...).Run()
	DelRule(rt)
	rargs := append(ipBin(rt.V6), "rule", "add", "pref", strconv.Itoa(rt.Table), "fwmark", fmt.Sprintf("0x%x", rt.Mark), "lookup", strconv.Itoa(rt.Table))
	if out, err := exec.Command(rargs[0], rargs[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(rargs, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// DelRule removes the fwmark rule (idempotent).
func DelRule(rt RouteTable) {
	for i := 0; i < 8; i++ {
		args := append(ipBin(rt.V6), "rule", "del", "pref", strconv.Itoa(rt.Table), "fwmark", fmt.Sprintf("0x%x", rt.Mark), "lookup", strconv.Itoa(rt.Table))
		if exec.Command(args[0], args[1:]...).Run() != nil {
			return
		}
	}
}

// DelRouteTable removes the table and rule.
func DelRouteTable(rt RouteTable) {
	DelRule(rt)
	args := append(ipBin(rt.V6), "route", "flush", "table", strconv.Itoa(rt.Table))
	_ = exec.Command(args[0], args[1:]...).Run()
}

// RouteTableExists checks for the default route in the table.
func RouteTableExists(rt RouteTable) bool {
	args := append(ipBin(rt.V6), "route", "show", "table", strconv.Itoa(rt.Table))
	out, err := exec.Command(args[0], args[1:]...).Output()
	return err == nil && strings.Contains(string(out), "default")
}

// --- kill switch ---

// KillSwitchOn blocks all outbound traffic except loopback, LAN ranges and
// the VPN endpoint until KillSwitchOff is called. One chain per profile.
func KillSwitchOn(name, endpoint string) error {
	chain := "CYBERBOBA_KS_" + strings.ToUpper(ifaceSafe(name))
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		v6 := bin == "ip6tables"
		_ = exec.Command(bin, xt([]string{"-t", "filter", "-N", chain})...).Run()
		_ = exec.Command(bin, xt([]string{"-t", "filter", "-F", chain})...).Run()
		rules := [][]string{{"-o", "lo", "-j", "RETURN"}}
		lan := []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
		if v6 {
			lan = []string{"::1/128", "fc00::/7", "fe80::/10"}
		}
		for _, cidr := range lan {
			rules = append(rules, []string{"-d", cidr, "-j", "RETURN"})
		}
		if host, _, err := net.SplitHostPort(endpoint); err == nil {
			if ips, err := net.LookupIP(host); err == nil {
				for _, ip := range ips {
					if (ip.To4() != nil) != v6 {
						rules = append(rules, []string{"-d", ip.String(), "-j", "RETURN"})
					}
				}
			}
		}
		rules = append(rules, []string{"-p", "udp", "--dport", "53", "-j", "RETURN"}) // keep name resolution for reconnects
		rules = append(rules, []string{"-j", "REJECT"})
		for _, r := range rules {
			args := xt(append([]string{"-t", "filter", "-A", chain}, r...))
			if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
				return fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
		}
		if exec.Command(bin, xt([]string{"-t", "filter", "-C", "OUTPUT", "-j", chain})...).Run() != nil {
			if out, err := exec.Command(bin, xt([]string{"-t", "filter", "-I", "OUTPUT", "1", "-j", chain})...).CombinedOutput(); err != nil {
				return fmt.Errorf("%s: %v: %s", bin, err, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

// KillSwitchOff removes the chain.
func KillSwitchOff(name string) error {
	chain := "CYBERBOBA_KS_" + strings.ToUpper(ifaceSafe(name))
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		for exec.Command(bin, xt([]string{"-t", "filter", "-C", "OUTPUT", "-j", chain})...).Run() == nil {
			if exec.Command(bin, xt([]string{"-t", "filter", "-D", "OUTPUT", "-j", chain})...).Run() != nil {
				break
			}
		}
		_ = exec.Command(bin, xt([]string{"-t", "filter", "-F", chain})...).Run()
		_ = exec.Command(bin, xt([]string{"-t", "filter", "-X", chain})...).Run()
	}
	return nil
}

// --- stealth (inbound) ---

// StealthOn silently drops unsolicited inbound packets (ZoneAlarm stealth) so
// the host is invisible to port scans, while keeping established/related
// replies, loopback, DHCP and (optionally) the Trusted Zone / LAN reachable.
func StealthOn(allowLAN bool) error {
	const chain = "CYBERBOBA_STEALTH"
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		v6 := bin == "ip6tables"
		_ = exec.Command(bin, xt([]string{"-N", chain})...).Run()
		_ = exec.Command(bin, xt([]string{"-F", chain})...).Run()
		rules := [][]string{
			{"-i", "lo", "-j", "RETURN"},
			{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"},
		}
		if !v6 {
			rules = append(rules, []string{"-p", "udp", "--sport", "67", "--dport", "68", "-j", "RETURN"})
		} else {
			rules = append(rules, []string{"-p", "udp", "--sport", "547", "--dport", "546", "-j", "RETURN"})
			rules = append(rules, []string{"-p", "ipv6-icmp", "-j", "RETURN"}) // NDP/RA needed for IPv6
		}
		if allowLAN {
			lan := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
			if v6 {
				lan = []string{"fc00::/7", "fe80::/10"}
			}
			for _, cidr := range lan {
				rules = append(rules, []string{"-s", cidr, "-j", "RETURN"})
			}
		}
		rules = append(rules, []string{"-j", "DROP"})
		for _, r := range rules {
			args := xt(append([]string{"-A", chain}, r...))
			if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
				return fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
		}
		if exec.Command(bin, xt([]string{"-C", "INPUT", "-j", chain})...).Run() != nil {
			if out, err := exec.Command(bin, xt([]string{"-I", "INPUT", "1", "-j", chain})...).CombinedOutput(); err != nil {
				return fmt.Errorf("%s: %v: %s", bin, err, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

// StealthOff removes the stealth chain.
func StealthOff() error {
	const chain = "CYBERBOBA_STEALTH"
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		for exec.Command(bin, xt([]string{"-C", "INPUT", "-j", chain})...).Run() == nil {
			if exec.Command(bin, xt([]string{"-D", "INPUT", "-j", chain})...).Run() != nil {
				break
			}
		}
		_ = exec.Command(bin, xt([]string{"-F", chain})...).Run()
		_ = exec.Command(bin, xt([]string{"-X", chain})...).Run()
	}
	return nil
}

func ifaceSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 16 {
		out = out[:16]
	}
	return out
}

// --- per-tag UDP policy (net_cls cgroup match) ---

// TagUDPSpec describes the UDP policy for one tagged cgroup.
type TagUDPSpec struct {
	Tag     string
	ClassID uint32 // net_cls classid
	Mark    uint32 // VPN fwmark, 0 for block
	Block   bool
}

const chainTagUDP = "CYBERBOBA_TAGUDP"

// ApplyTagUDP rebuilds the mangle OUTPUT chain that marks or drops UDP from
// tagged cgroups. DNS (UDP/53) is left alone so name resolution keeps
// working through the forwarder.
func ApplyTagUDP(specs []TagUDPSpec) error {
	bin := "iptables"
	if _, err := exec.LookPath(bin); err != nil {
		return nil
	}
	run := func(args ...string) error {
		out, err := exec.Command(bin, append([]string{"-w", "5"}, args...)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	exists := func(args ...string) bool {
		return exec.Command(bin, append([]string{"-w", "5"}, args...)...).Run() == nil
	}
	_ = run("-t", "mangle", "-N", chainTagUDP)
	if err := run("-t", "mangle", "-F", chainTagUDP); err != nil {
		return err
	}
	// Keep DNS flowing normally.
	if err := run("-t", "mangle", "-A", chainTagUDP, "-p", "udp", "--dport", "53", "-j", "RETURN"); err != nil {
		return err
	}
	for _, sp := range specs {
		cid := fmt.Sprintf("0x%08x", sp.ClassID)
		if sp.Block {
			if err := run("-t", "mangle", "-A", chainTagUDP, "-m", "cgroup", "--cgroup", cid, "-p", "udp", "-j", "MARK", "--set-mark", "0x1"); err != nil {
				return err
			}
			continue
		}
		if err := run("-t", "mangle", "-A", chainTagUDP, "-m", "cgroup", "--cgroup", cid, "-p", "udp",
			"-j", "MARK", "--set-xmark", fmt.Sprintf("0x%x/0xffffffff", sp.Mark)); err != nil {
			return err
		}
	}
	if !exists("-t", "mangle", "-C", "OUTPUT", "-j", chainTagUDP) {
		if err := run("-t", "mangle", "-I", "OUTPUT", "1", "-j", chainTagUDP); err != nil {
			return err
		}
	}
	// Drop packets marked 0x1 (tag block) in filter OUTPUT.
	_ = run("-t", "filter", "-C", "OUTPUT", "-m", "mark", "--mark", "0x1", "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable")
	if !exists("-t", "filter", "-C", "OUTPUT", "-m", "mark", "--mark", "0x1", "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable") {
		_ = run("-t", "filter", "-I", "OUTPUT", "1", "-m", "mark", "--mark", "0x1", "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable")
	}
	return nil
}

// ClearTagUDP removes the tag UDP chain and its hooks.
func ClearTagUDP() {
	bin := "iptables"
	if _, err := exec.LookPath(bin); err != nil {
		return
	}
	run := func(args ...string) { _ = exec.Command(bin, append([]string{"-w", "5"}, args...)...).Run() }
	for exec.Command(bin, "-w", "5", "-t", "mangle", "-C", "OUTPUT", "-j", chainTagUDP).Run() == nil {
		if exec.Command(bin, "-w", "5", "-t", "mangle", "-D", "OUTPUT", "-j", chainTagUDP).Run() != nil {
			break
		}
	}
	for exec.Command(bin, "-w", "5", "-t", "filter", "-C", "OUTPUT", "-m", "mark", "--mark", "0x1", "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable").Run() == nil {
		if exec.Command(bin, "-w", "5", "-t", "filter", "-D", "OUTPUT", "-m", "mark", "--mark", "0x1", "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable").Run() != nil {
			break
		}
	}
	run("-t", "mangle", "-F", chainTagUDP)
	run("-t", "mangle", "-X", chainTagUDP)
}
