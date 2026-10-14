// Package rules implements the ordered first-match rule engine.
package rules

import (
	"net"
	"net/netip"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"cyberboba/internal/config"
)

// Conn describes a connection to be classified.
type Conn struct {
	App   string // process name (comm / basename of exe)
	Exe   string // absolute path of executable
	Cmd   string // command line (space-joined)
	Tag   string // CYBERBOBA_TAG environment value
	User  string // owner user name
	UID   int    // owner uid (-1 if unknown)
	Host  string // hostname if known (from DNS cache / SNI / Host)
	IP    netip.Addr
	Port  int
	Proto string // "tcp" | "udp"
}

// Decision is the outcome of evaluation.
type Decision struct {
	Matched bool
	Index   int
	Rule    *config.Rule
	Action  config.Action
	Proxy   string
	VPN     string
}

type portRange struct{ lo, hi int }

type target struct {
	prefix  netip.Prefix
	isCIDR  bool
	host    string // lower-case, may start with "*."
	isLAN   bool
	wildAll bool
}

type compiled struct {
	rule     *config.Rule
	index    int
	apps     []string // lower-case patterns
	users    []string
	targets  []target
	ports    []portRange
	protos   map[string]bool
	hasApps  bool
	hasUsers bool
}

// Engine is an immutable compiled rule set; build a new one on config change.
type Engine struct {
	rules []compiled
}

var lanPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// IsLAN reports whether ip belongs to a loopback, link-local or private range.
func IsLAN(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range lanPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Compile builds an Engine from the rule list.
func Compile(rs []config.Rule) *Engine {
	e := &Engine{}
	for i := range rs {
		r := &rs[i]
		if !r.IsEnabled() {
			continue
		}
		c := compiled{rule: r, index: i, protos: map[string]bool{}}
		for _, a := range r.Apps {
			a = strings.TrimSpace(a)
			if a != "" {
				c.apps = append(c.apps, strings.ToLower(a))
			}
		}
		c.hasApps = len(c.apps) > 0
		for _, u := range r.Users {
			if u = strings.TrimSpace(u); u != "" {
				c.users = append(c.users, u)
			}
		}
		c.hasUsers = len(c.users) > 0
		for _, t := range r.Targets {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" {
				continue
			}
			switch {
			case t == "*", t == "any", t == "all":
				c.targets = append(c.targets, target{wildAll: true})
			case t == "lan", t == "local", t == "private":
				c.targets = append(c.targets, target{isLAN: true})
			default:
				if p, err := netip.ParsePrefix(t); err == nil {
					c.targets = append(c.targets, target{prefix: p.Masked(), isCIDR: true})
				} else if a, err := netip.ParseAddr(t); err == nil {
					c.targets = append(c.targets, target{prefix: netip.PrefixFrom(a, a.BitLen()), isCIDR: true})
				} else {
					c.targets = append(c.targets, target{host: strings.TrimSuffix(t, ".")})
				}
			}
		}
		for _, p := range r.Ports {
			lo, hi, err := config.ParsePortRange(p)
			if err == nil {
				c.ports = append(c.ports, portRange{lo, hi})
			}
		}
		for _, p := range r.Protocols {
			c.protos[strings.ToLower(strings.TrimSpace(p))] = true
		}
		e.rules = append(e.rules, c)
	}
	return e
}

// Evaluate returns the first matching rule. If nothing matches the decision
// is Matched=false with Action=direct.
func (e *Engine) Evaluate(c Conn) Decision {
	for i := range e.rules {
		r := &e.rules[i]
		if r.matches(c) {
			return Decision{Matched: true, Index: r.index, Rule: r.rule, Action: r.rule.Action, Proxy: r.rule.Proxy, VPN: r.rule.VPN}
		}
	}
	return Decision{Action: config.ActionDirect}
}

func (r *compiled) matches(c Conn) bool {
	if len(r.protos) > 0 && c.Proto != "" && !r.protos[c.Proto] {
		return false
	}
	if len(r.ports) > 0 {
		ok := false
		for _, p := range r.ports {
			if c.Port >= p.lo && c.Port <= p.hi {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if r.hasUsers && !matchUser(r.users, c) {
		return false
	}
	if r.hasApps && !matchApp(r.apps, c) {
		return false
	}
	if len(r.targets) > 0 && !matchTarget(r.targets, c) {
		return false
	}
	return true
}

func matchUser(users []string, c Conn) bool {
	for _, u := range users {
		if u == c.User {
			return true
		}
		if n, err := strconv.Atoi(u); err == nil && n == c.UID {
			return true
		}
	}
	return false
}

// MatchApp reports whether any of pats matches the connection's app/exe/cmd/tag.
func MatchApp(pats []string, c Conn) bool { return matchApp(pats, c) }

func matchApp(pats []string, c Conn) bool {
	app := strings.ToLower(c.App)
	exe := strings.ToLower(c.Exe)
	base := strings.ToLower(filepath.Base(c.Exe))
	cmd := strings.ToLower(c.Cmd)
	for _, p := range pats {
		switch {
		case strings.HasPrefix(p, "tag:"):
			if c.Tag != "" && strings.EqualFold(c.Tag, p[4:]) {
				return true
			}
		case strings.HasPrefix(p, "cmd:"):
			if cmd != "" && strings.Contains(cmd, p[4:]) {
				return true
			}
		case strings.HasPrefix(p, "/"):
			if exe == p {
				return true
			}
			if ok, _ := path.Match(p, exe); ok {
				return true
			}
		default:
			if app == p || base == p {
				return true
			}
			if strings.ContainsAny(p, "*?[") {
				if ok, _ := path.Match(p, app); ok {
					return true
				}
				if ok, _ := path.Match(p, base); ok {
					return true
				}
			}
		}
	}
	return false
}

func matchTarget(ts []target, c Conn) bool {
	host := strings.ToLower(strings.TrimSuffix(c.Host, "."))
	for _, t := range ts {
		switch {
		case t.wildAll:
			return true
		case t.isLAN:
			if c.IP.IsValid() && IsLAN(c.IP) {
				return true
			}
			if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") {
				return true
			}
		case t.isCIDR:
			if c.IP.IsValid() && t.prefix.Contains(c.IP.Unmap()) {
				return true
			}
		default:
			if host == "" {
				continue
			}
			if MatchHost(t.host, host) {
				return true
			}
		}
	}
	return false
}

// MatchHost matches a hostname against a pattern: exact, "*.example.com"
// (any subdomain, also matches example.com itself), "*foo*" (glob).
func MatchHost(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		if strings.HasSuffix(host, suffix) || host == pattern[2:] {
			return true
		}
		return false
	}
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(host, pattern)
	}
	if strings.ContainsAny(pattern, "*?[") {
		ok, _ := path.Match(pattern, host)
		return ok
	}
	return false
}

// ResolveIP is a tiny helper used by the rule tester.
func ResolveIP(s string) netip.Addr {
	if a, err := netip.ParseAddr(s); err == nil {
		return a
	}
	if ip := net.ParseIP(s); ip != nil {
		if a, ok := netip.AddrFromSlice(ip); ok {
			return a
		}
	}
	return netip.Addr{}
}
