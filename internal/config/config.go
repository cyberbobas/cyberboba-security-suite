// Package config defines the on-disk configuration of cyberboba and helpers to
// load, validate and persist it.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Action is what happens to a connection that matched a rule.
type Action string

const (
	ActionDirect Action = "direct"
	ActionProxy  Action = "proxy"
	ActionVPN    Action = "vpn"
	ActionBlock  Action = "block"
	// ActionIntercept terminates the connection in the built-in intercepting
	// proxy (TLS MITM) and forwards it according to intercept.upstream.
	ActionIntercept Action = "intercept"
)

// ProxyType is the protocol spoken to an upstream proxy.
type ProxyType string

const (
	ProxySOCKS5   ProxyType = "socks5"
	ProxySOCKS4   ProxyType = "socks4"
	ProxyHTTP     ProxyType = "http"
	ProxyChain    ProxyType = "chain"
	ProxyFailover ProxyType = "failover"
	ProxyBalance  ProxyType = "balance"
	ProxyRotate   ProxyType = "rotate"
)

// VPNType selects the VPN backend.
type VPNType string

const (
	VPNWireGuard VPNType = "wireguard"
	VPNOpenVPN   VPNType = "openvpn"
)

// VPNMode decides whether a tunnel captures all traffic or only traffic that
// rules explicitly send to it.
type VPNMode string

const (
	// VPNModeFull: the tunnel installs its own default route (classic VPN).
	VPNModeFull VPNMode = "full"
	// VPNModeSelective: the tunnel does not touch the main routing table;
	// only connections whose rule says `action: vpn` go through it.
	VPNModeSelective VPNMode = "selective"
)

// Rule is one entry of the ordered rule list. First match wins.
type Rule struct {
	Name    string `yaml:"name" json:"name"`
	Enabled *bool  `yaml:"enabled,omitempty" json:"enabled"`
	Comment string `yaml:"comment,omitempty" json:"comment,omitempty"`
	// Apps: process names ("firefox"), absolute paths ("/usr/bin/curl"),
	// glob patterns ("*telegram*") or tags ("tag:work", set with `cyberboba run --tag`).
	Apps []string `yaml:"apps,omitempty" json:"apps,omitempty"`
	// Users: owner user names or numeric uids.
	Users []string `yaml:"users,omitempty" json:"users,omitempty"`
	// Targets: hostnames, "*.example.com", IPs, CIDRs, "lan" (RFC1918 + loopback).
	Targets []string `yaml:"targets,omitempty" json:"targets,omitempty"`
	// Ports: "443", "80-90", "1024-65535".
	Ports []string `yaml:"ports,omitempty" json:"ports,omitempty"`
	// Protocols: tcp, udp (udp currently only covers DNS).
	Protocols []string `yaml:"protocols,omitempty" json:"protocols,omitempty"`

	Action Action `yaml:"action" json:"action"`
	// Proxy: name of a proxy or chain, used when Action == proxy.
	Proxy string `yaml:"proxy,omitempty" json:"proxy,omitempty"`
	// VPN: name of a VPN profile, used when Action == vpn.
	VPN string `yaml:"vpn,omitempty" json:"vpn,omitempty"`
}

// IsEnabled returns true unless Enabled is explicitly false.
func (r Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// Proxy is an upstream proxy server, or a chain of them.
type Proxy struct {
	Name     string    `yaml:"name" json:"name"`
	Type     ProxyType `yaml:"type" json:"type"`
	Addr     string    `yaml:"addr,omitempty" json:"addr,omitempty"`
	Username string    `yaml:"username,omitempty" json:"username,omitempty"`
	Password string    `yaml:"password,omitempty" json:"password,omitempty"`
	// Hops: names of proxies, in order, for Type == chain.
	Hops []string `yaml:"hops,omitempty" json:"hops,omitempty"`
	// ViaVPN: reach the proxy (or first hop) through this VPN profile.
	ViaVPN string `yaml:"via_vpn,omitempty" json:"via_vpn,omitempty"`
	// RemoteDNS: resolve hostnames on the proxy side instead of locally.
	RemoteDNS bool `yaml:"remote_dns,omitempty" json:"remote_dns"`
	// RotateEverySec: for type "rotate", how often (seconds) to switch the
	// active member. RotateMode is "random" (default) or "sequential".
	RotateEverySec int    `yaml:"rotate_every_sec,omitempty" json:"rotate_every_sec,omitempty"`
	RotateMode     string `yaml:"rotate_mode,omitempty" json:"rotate_mode,omitempty"`
	Comment        string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// VPN is a WireGuard or OpenVPN profile.
type VPN struct {
	Name      string  `yaml:"name" json:"name"`
	Type      VPNType `yaml:"type" json:"type"`
	Config    string  `yaml:"config" json:"config"`
	Mode      VPNMode `yaml:"mode,omitempty" json:"mode"`
	Autostart bool    `yaml:"autostart,omitempty" json:"autostart"`
	// AuthFile: OpenVPN --auth-user-pass file (optional).
	AuthFile string `yaml:"auth_file,omitempty" json:"auth_file,omitempty"`
	// Username/Password: OpenVPN credentials; written to a private auth file.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
	// KillSwitch: block non-VPN traffic while the tunnel is down after
	// having been up (full mode).
	KillSwitch bool `yaml:"kill_switch,omitempty" json:"kill_switch"`
	// Reconnect: restart the backend when it exits unexpectedly.
	Reconnect bool `yaml:"reconnect,omitempty" json:"reconnect"`
	// ExtraArgs: additional openvpn command line arguments.
	ExtraArgs []string `yaml:"extra_args,omitempty" json:"extra_args,omitempty"`
	// Interface: override interface name (WireGuard: derived from config name).
	Interface string `yaml:"interface,omitempty" json:"interface,omitempty"`
	Comment   string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// VPNRotation cycles the active tunnel among a set of VPN profiles on a timer,
// so a rule routing to the rotation name uses a different tunnel every interval.
type VPNRotation struct {
	Name     string   `yaml:"name" json:"name"`
	Enabled  bool     `yaml:"enabled" json:"enabled"`
	VPNs     []string `yaml:"vpns" json:"vpns"`
	EverySec int      `yaml:"every_sec,omitempty" json:"every_sec,omitempty"`
	Mode     string   `yaml:"mode,omitempty" json:"mode,omitempty"` // random | sequential
	Comment  string   `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// Caido holds integration settings for the Caido HTTP proxy.
type Caido struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Managed: cyberboba starts and stops caido-cli itself.
	Managed bool   `yaml:"managed" json:"managed"`
	Binary  string `yaml:"binary,omitempty" json:"binary,omitempty"`
	// Listen: address of the Caido proxy listener (also used for the UI).
	Listen   string `yaml:"listen" json:"listen"`
	DataPath string `yaml:"data_path,omitempty" json:"data_path,omitempty"`
	// CACert: path to Caido's CA certificate (ca.crt) exported from the UI.
	CACert string `yaml:"ca_cert,omitempty" json:"ca_cert,omitempty"`
	// ExtraArgs for caido-cli.
	ExtraArgs []string `yaml:"extra_args,omitempty" json:"extra_args,omitempty"`
	// ProxyName: name of the auto-generated proxy entry that targets Caido.
	ProxyName string `yaml:"proxy_name,omitempty" json:"proxy_name,omitempty"`
}

// Route is a reusable "how to reach the network" triple.
type Route struct {
	Action Action `yaml:"action" json:"action"`
	Proxy  string `yaml:"proxy,omitempty" json:"proxy,omitempty"`
	VPN    string `yaml:"vpn,omitempty" json:"vpn,omitempty"`
}

// Scope lists host patterns.
type Scope struct {
	Include []string `yaml:"include" json:"include"`
	Exclude []string `yaml:"exclude" json:"exclude"`
}

// Rewrite is a match & replace rule applied to intercepted flows.
type Rewrite struct {
	Name    string   `yaml:"name" json:"name"`
	Enabled *bool    `yaml:"enabled,omitempty" json:"enabled"`
	Target  string   `yaml:"target" json:"target"` // request | response
	Part    string   `yaml:"part" json:"part"`     // header | body | url
	Header  string   `yaml:"header,omitempty" json:"header,omitempty"`
	Match   string   `yaml:"match,omitempty" json:"match,omitempty"`
	Replace string   `yaml:"replace,omitempty" json:"replace,omitempty"`
	Remove  bool     `yaml:"remove,omitempty" json:"remove"`
	Hosts   []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
}

// IsEnabled reports whether a rewrite is active.
func (w Rewrite) IsEnabled() bool { return w.Enabled == nil || *w.Enabled }

// Intercept configures the built-in intercepting HTTP proxy.
type Intercept struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Listen: explicit HTTP proxy listener (CONNECT + absolute URI).
	Listen string `yaml:"listen" json:"listen"`
	// CADir holds ca.crt / ca.key.
	CADir         string `yaml:"ca_dir,omitempty" json:"ca_dir"`
	HoldRequests  bool   `yaml:"hold_requests" json:"hold_requests"`
	HoldResponses bool   `yaml:"hold_responses" json:"hold_responses"`
	// RecordOnlyScope: do not record flows outside the scope.
	RecordOnlyScope bool  `yaml:"record_only_scope" json:"record_only_scope"`
	Scope           Scope `yaml:"scope" json:"scope"`
	// Passthrough: hosts that are tunneled without TLS termination.
	Passthrough []string `yaml:"passthrough" json:"passthrough"`
	// Upstream: how forwarded requests leave the machine.
	Upstream          Route     `yaml:"upstream" json:"upstream"`
	VerifyUpstreamTLS bool      `yaml:"verify_upstream_tls" json:"verify_upstream_tls"`
	MaxFlows          int       `yaml:"max_flows,omitempty" json:"max_flows"`
	MaxBody           int       `yaml:"max_body,omitempty" json:"max_body"`
	Rewrites          []Rewrite `yaml:"rewrites,omitempty" json:"rewrites"`
	// SessionDir stores saved intercept sessions.
	SessionDir string `yaml:"session_dir,omitempty" json:"session_dir"`
}

// FwProgram is one application's firewall permissions (ZoneAlarm-style).
// App is a matcher like a rule's apps entry: process name, absolute path,
// glob, "cmd:SUBSTR" or "tag:NAME".
type FwProgram struct {
	App      string `yaml:"app" json:"app"`
	Trusted  string `yaml:"trusted,omitempty" json:"trusted"`   // allow | block | ask
	Internet string `yaml:"internet,omitempty" json:"internet"` // allow | block | ask
	Server   string `yaml:"server,omitempty" json:"server"`     // allow | block (accept inbound)
	LockPass bool   `yaml:"lock_pass,omitempty" json:"lock_pass"`
	Comment  string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// Firewall is a ZoneAlarm-style application firewall layered on top of the
// routing rules: it decides WHETHER a program may reach the network (per zone),
// prompting for unknown programs, with an Internet Lock and inbound stealth.
type Firewall struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Mode governs UNKNOWN programs (no entry below): off | ask | auto | block.
	// off = allow all, ask = prompt, auto = allow & remember, block = deny.
	Mode string `yaml:"mode,omitempty" json:"mode"`
	// TrustedNets: CIDRs (or "lan") treated as the Trusted Zone.
	TrustedNets []string `yaml:"trusted_nets,omitempty" json:"trusted_nets"`
	// Stealth: drop unsolicited inbound so ports are invisible to scans.
	Stealth bool `yaml:"stealth,omitempty" json:"stealth"`
	// AllowLANInbound: accept inbound from the Trusted Zone (file/printer sharing).
	AllowLANInbound bool `yaml:"allow_lan_inbound,omitempty" json:"allow_lan_inbound"`
	// InternetLock: panic lock — block everything except lock_pass programs.
	InternetLock bool `yaml:"internet_lock,omitempty" json:"internet_lock"`
	// AskTimeoutSec: how long a held connection waits for a decision.
	// 0 means wait until the user answers (no auto-timeout).
	AskTimeoutSec int `yaml:"ask_timeout_sec,omitempty" json:"ask_timeout_sec"`
	// AskTimeoutAction: what to do on timeout (allow | block).
	AskTimeoutAction string      `yaml:"ask_timeout_action,omitempty" json:"ask_timeout_action"`
	Programs         []FwProgram `yaml:"programs,omitempty" json:"programs"`
	// BlockedHosts: destination patterns (hostname, *.domain, glob, IP, CIDR)
	// that are denied for every program, regardless of mode — populated by the
	// "block" button on the live map. Enforced whenever the firewall engine is
	// loaded, even if program control is otherwise off.
	BlockedHosts []string `yaml:"blocked_hosts,omitempty" json:"blocked_hosts"`
}

// Geo configures IP geolocation used by the traffic map. Lookups go to an
// external HTTP service, so it is opt-outable; results are cached in memory.
type Geo struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Provider is a URL template; {ip} is replaced with the address to look up.
	// It must return JSON with countryCode/country/city/isp-style fields.
	Provider string `yaml:"provider,omitempty" json:"provider"`
	// CacheTTLHours controls how long a successful lookup is reused.
	CacheTTLHours int `yaml:"cache_ttl_hours,omitempty" json:"cache_ttl_hours"`
}

// Proxifier controls the transparent interception engine.
type Proxifier struct {
	// Enabled: install netfilter rules at daemon start.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// ListenTCP: transparent TCP listener (loopback only).
	ListenTCP string `yaml:"listen_tcp" json:"listen_tcp"`
	// ListenDNS: DNS forwarder listener.
	ListenDNS string `yaml:"listen_dns" json:"listen_dns"`
	// ListenSOCKS: optional inbound SOCKS5 listener for applications with
	// proxy settings (works without root). Empty disables it.
	ListenSOCKS string `yaml:"listen_socks,omitempty" json:"listen_socks"`
	// ListenHTTP: optional inbound HTTP proxy listener (CONNECT + plain HTTP).
	ListenHTTP string `yaml:"listen_http,omitempty" json:"listen_http"`
	// DNSUpstream: resolver used by the forwarder (host:port).
	DNSUpstream string `yaml:"dns_upstream" json:"dns_upstream"`
	// DNSViaRules: if true, DNS queries are routed with the same rule engine
	// as TCP (matching on the querying process is not possible for UDP, so
	// the "dns" pseudo-app is used).
	DNSViaRules bool `yaml:"dns_via_rules" json:"dns_via_rules"`
	// BlockQUIC: drop outbound UDP/443 so browsers fall back to TCP, which
	// makes HTTPS visible to Caido and proxies.
	BlockQUIC bool `yaml:"block_quic" json:"block_quic"`
	// IPv6: also intercept IPv6 traffic.
	IPv6 bool `yaml:"ipv6" json:"ipv6"`
	// SniffHostnames: peek TLS SNI / HTTP Host to match hostname rules.
	SniffHostnames bool `yaml:"sniff_hostnames" json:"sniff_hostnames"`
	// MarkBase: fwmark base used for daemon sockets (bypass) and VPN tables.
	MarkBase uint32 `yaml:"mark_base,omitempty" json:"mark_base"`
	// TableBase: first routing table number for selective VPNs.
	TableBase int `yaml:"table_base,omitempty" json:"table_base"`
}

// API controls the control socket / web UI.
type API struct {
	UnixSocket string `yaml:"unix_socket" json:"unix_socket"`
	// Listen: optional TCP listener for the web UI (e.g. 127.0.0.1:7471).
	Listen string `yaml:"listen,omitempty" json:"listen,omitempty"`
	// Token: optional bearer token required for the TCP listener.
	Token string `yaml:"token,omitempty" json:"token,omitempty"`
}

// DNSFilter configures Pi-hole-style DNS blocking of ad / tracker / malware
// domains. Lists are downloaded from Blocklists (hosts or domain format) and
// merged with the manual Block entries; Allow always wins. A blocked query is
// answered with NXDOMAIN (Sinkhole "nxdomain", default) or 0.0.0.0/:: ("zero").
type DNSFilter struct {
	Enabled    bool     `yaml:"enabled" json:"enabled"`
	Blocklists []string `yaml:"blocklists,omitempty" json:"blocklists"`
	Block      []string `yaml:"block,omitempty" json:"block"`
	Allow      []string `yaml:"allow,omitempty" json:"allow"`
	Sinkhole   string   `yaml:"sinkhole,omitempty" json:"sinkhole"`
}

// Bandwidth tunes the per-application bandwidth meter.
type Bandwidth struct {
	Alerts BandwidthAlerts `yaml:"alerts" json:"alerts"`
}

// BandwidthAlerts controls the "application is sending/receiving an abnormal
// amount of data" detector. An alert fires when an app's live upload (or
// download) rate both exceeds the absolute Floor and runs Factor times over
// its own recent baseline for Sustain seconds, at most once per Cooldown.
type BandwidthAlerts struct {
	Enabled      bool    `yaml:"enabled" json:"enabled"`
	FloorKBps    float64 `yaml:"floor_kbps,omitempty" json:"floor_kbps"`       // ignore spikes below this rate (KB/s)
	Factor       float64 `yaml:"factor,omitempty" json:"factor"`               // times over the app's own baseline
	SustainSecs  int     `yaml:"sustain_secs,omitempty" json:"sustain_secs"`   // spike must persist this long
	CooldownSecs int     `yaml:"cooldown_secs,omitempty" json:"cooldown_secs"` // min seconds between alerts per app
}

// Config is the root document.
type Config struct {
	Proxifier    Proxifier     `yaml:"proxifier" json:"proxifier"`
	API          API           `yaml:"api" json:"api"`
	Caido        Caido         `yaml:"caido" json:"caido"`
	Intercept    Intercept     `yaml:"intercept" json:"intercept"`
	Geo          Geo           `yaml:"geo" json:"geo"`
	Firewall     Firewall      `yaml:"firewall" json:"firewall"`
	DNSFilter    DNSFilter     `yaml:"dns_filter" json:"dns_filter"`
	Bandwidth    Bandwidth     `yaml:"bandwidth" json:"bandwidth"`
	Proxies      []Proxy       `yaml:"proxies" json:"proxies"`
	VPNs         []VPN         `yaml:"vpns" json:"vpns"`
	VPNRotations []VPNRotation `yaml:"vpn_rotations,omitempty" json:"vpn_rotations,omitempty"`
	Rules        []Rule        `yaml:"rules" json:"rules"`
	LogLevel     string        `yaml:"log_level,omitempty" json:"log_level"`
	// MaxConnLog: how many finished connections to keep in memory.
	MaxConnLog int `yaml:"max_conn_log,omitempty" json:"max_conn_log"`
}

// DefaultPath is where the daemon looks for its configuration.
const DefaultPath = "/etc/cyberboba/config.yaml"

// Default returns a sensible configuration for a desktop machine.
func Default() *Config {
	t := true
	return &Config{
		Proxifier: Proxifier{
			Enabled:        true,
			ListenTCP:      "127.0.0.1:7470",
			ListenDNS:      "127.0.0.1:7453",
			ListenSOCKS:    "127.0.0.1:7472",
			ListenHTTP:     "127.0.0.1:7473",
			DNSUpstream:    "1.1.1.1:53",
			DNSViaRules:    true,
			BlockQUIC:      true,
			IPv6:           true,
			SniffHostnames: true,
			MarkBase:       0x7400,
			TableBase:      7400,
		},
		API: API{
			UnixSocket: "/run/cyberboba/cyberboba.sock",
			Listen:     "127.0.0.1:7471",
		},
		Caido: Caido{
			Enabled:   false,
			Managed:   true,
			Listen:    "127.0.0.1:8080",
			ProxyName: "caido",
		},
		Intercept: Intercept{
			Enabled:  true,
			Listen:   "127.0.0.1:8080",
			CADir:    "/etc/cyberboba/ca",
			Scope:    Scope{Include: []string{}, Exclude: []string{}},
			Upstream: Route{Action: ActionDirect},
			MaxFlows: 10000,
			MaxBody:  1 << 20,
		},
		Geo: Geo{
			Enabled:       true,
			Provider:      "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,query",
			CacheTTLHours: 24,
		},
		Firewall: Firewall{
			Enabled:          false,
			Mode:             "ask",
			TrustedNets:      []string{"lan"},
			Stealth:          false,
			AllowLANInbound:  true,
			AskTimeoutSec:    20,
			AskTimeoutAction: "allow",
			Programs:         []FwProgram{},
		},
		Proxies: []Proxy{},
		VPNs:    []VPN{},
		Rules: []Rule{
			{Name: "Localhost and LAN", Enabled: &t, Targets: []string{"lan"}, Action: ActionDirect},
			{Name: "Default", Enabled: &t, Action: ActionDirect},
		},
		Bandwidth: Bandwidth{
			Alerts: BandwidthAlerts{Enabled: true, FloorKBps: 800, Factor: 8, SustainSecs: 4, CooldownSecs: 120},
		},
		LogLevel:   "info",
		MaxConnLog: 2000,
	}
}

// Load reads and validates a configuration file. A missing file yields the
// default configuration (and no error) when allowMissing is true.
func Load(path string, allowMissing bool) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			return Default(), nil
		}
		return nil, err
	}
	return Parse(data)
}

// Parse decodes YAML on top of the defaults and validates the result.
func Parse(data []byte) (*Config, error) {
	c := Default()
	// Lists are replaced, not merged, so clear defaults that the user
	// overrides explicitly.
	var probe struct {
		Rules   *[]Rule  `yaml:"rules"`
		Proxies *[]Proxy `yaml:"proxies"`
		VPNs    *[]VPN   `yaml:"vpns"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if probe.Rules != nil {
		c.Rules = nil
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Save writes the configuration atomically.
func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Marshal returns the YAML form.
func (c *Config) Marshal() ([]byte, error) { return yaml.Marshal(c) }

// ProxyByName finds a proxy.
func (c *Config) ProxyByName(name string) *Proxy {
	for i := range c.Proxies {
		if c.Proxies[i].Name == name {
			return &c.Proxies[i]
		}
	}
	return nil
}

// VPNByName finds a VPN profile.
func (c *Config) VPNByName(name string) *VPN {
	for i := range c.VPNs {
		if c.VPNs[i].Name == name {
			return &c.VPNs[i]
		}
	}
	return nil
}

// VPNRotationByName returns a VPN rotation by name, or nil.
func (c *Config) VPNRotationByName(name string) *VPNRotation {
	for i := range c.VPNRotations {
		if c.VPNRotations[i].Name == name {
			return &c.VPNRotations[i]
		}
	}
	return nil
}

// VPNIndex returns the stable index of a VPN profile used to derive its fwmark
// and routing table, or -1.
func (c *Config) VPNIndex(name string) int {
	for i := range c.VPNs {
		if c.VPNs[i].Name == name {
			return i
		}
	}
	return -1
}

// BypassMark is the fwmark set on every socket the daemon opens itself so
// netfilter does not redirect it back into the daemon.
func (c *Config) BypassMark() uint32 { return c.Proxifier.MarkBase }

// VPNMark returns the fwmark that routes a socket through the selective VPN
// with the given index (1-based inside the mark range).
func (c *Config) VPNMark(idx int) uint32 { return c.Proxifier.MarkBase + 1 + uint32(idx) }

// VPNTable returns the routing table number for a selective VPN.
func (c *Config) VPNTable(idx int) int { return c.Proxifier.TableBase + 1 + idx }

// Validate checks referential integrity and basic syntax.
func (c *Config) Validate() error {
	var errs []string
	seen := map[string]bool{}
	for i, p := range c.Proxies {
		if p.Name == "" {
			errs = append(errs, fmt.Sprintf("proxies[%d]: name is required", i))
		}
		if seen["p:"+p.Name] {
			errs = append(errs, fmt.Sprintf("proxies[%d]: duplicate name %q", i, p.Name))
		}
		seen["p:"+p.Name] = true
		switch p.Type {
		case ProxySOCKS5, ProxySOCKS4, ProxyHTTP:
			if _, _, err := net.SplitHostPort(p.Addr); err != nil {
				errs = append(errs, fmt.Sprintf("proxy %q: bad addr %q", p.Name, p.Addr))
			}
		case ProxyChain, ProxyFailover, ProxyBalance:
			if len(p.Hops) == 0 {
				errs = append(errs, fmt.Sprintf("proxy %q: %s needs hops", p.Name, p.Type))
			}
		case ProxyRotate:
			if len(p.Hops) == 0 {
				errs = append(errs, fmt.Sprintf("proxy %q: rotate needs hops", p.Name))
			}
			if c.Proxies[i].RotateEverySec <= 0 {
				c.Proxies[i].RotateEverySec = 300
			}
			if c.Proxies[i].RotateMode == "" {
				c.Proxies[i].RotateMode = "random"
			}
			if c.Proxies[i].RotateMode != "random" && c.Proxies[i].RotateMode != "sequential" {
				errs = append(errs, fmt.Sprintf("proxy %q: rotate_mode must be random|sequential", p.Name))
			}
		default:
			errs = append(errs, fmt.Sprintf("proxy %q: unknown type %q", p.Name, p.Type))
		}
	}
	for _, p := range c.Proxies {
		for _, h := range p.Hops {
			hp := c.ProxyByName(h)
			if hp == nil {
				errs = append(errs, fmt.Sprintf("proxy %q: unknown hop %q", p.Name, h))
			} else if hp.Type == ProxyChain || hp.Type == ProxyFailover || hp.Type == ProxyBalance || hp.Type == ProxyRotate {
				errs = append(errs, fmt.Sprintf("proxy %q: hop %q is itself a group (%s)", p.Name, h, hp.Type))
			}
		}
		if p.ViaVPN != "" && c.VPNByName(p.ViaVPN) == nil {
			errs = append(errs, fmt.Sprintf("proxy %q: unknown via_vpn %q", p.Name, p.ViaVPN))
		}
	}
	for i := range c.VPNs {
		v := &c.VPNs[i]
		if v.Name == "" {
			errs = append(errs, fmt.Sprintf("vpns[%d]: name is required", i))
		}
		if seen["v:"+v.Name] {
			errs = append(errs, fmt.Sprintf("vpns[%d]: duplicate name %q", i, v.Name))
		}
		seen["v:"+v.Name] = true
		if v.Type != VPNWireGuard && v.Type != VPNOpenVPN {
			errs = append(errs, fmt.Sprintf("vpn %q: unknown type %q", v.Name, v.Type))
		}
		if v.Config == "" {
			errs = append(errs, fmt.Sprintf("vpn %q: config path is required", v.Name))
		}
		if v.Mode == "" {
			v.Mode = VPNModeFull
		}
		if v.Mode != VPNModeFull && v.Mode != VPNModeSelective {
			errs = append(errs, fmt.Sprintf("vpn %q: unknown mode %q", v.Name, v.Mode))
		}
		if v.Type == VPNWireGuard && !strings.HasSuffix(v.Config, ".conf") {
			errs = append(errs, fmt.Sprintf("vpn %q: wireguard config must end with .conf (wg-quick requirement)", v.Name))
		}
	}
	if len(c.VPNs) > 200 {
		errs = append(errs, "too many vpn profiles (max 200)")
	}
	for i := range c.VPNRotations {
		vr := &c.VPNRotations[i]
		if vr.Name == "" {
			errs = append(errs, fmt.Sprintf("vpn_rotations[%d]: name is required", i))
		}
		if c.VPNByName(vr.Name) != nil {
			errs = append(errs, fmt.Sprintf("vpn_rotation %q: name collides with a VPN profile", vr.Name))
		}
		if len(vr.VPNs) < 1 {
			errs = append(errs, fmt.Sprintf("vpn_rotation %q: needs at least one vpn", vr.Name))
		}
		for _, n := range vr.VPNs {
			if c.VPNByName(n) == nil {
				errs = append(errs, fmt.Sprintf("vpn_rotation %q: unknown vpn %q", vr.Name, n))
			}
		}
		if vr.EverySec <= 0 {
			vr.EverySec = 300
		}
		if vr.Mode == "" {
			vr.Mode = "random"
		}
		if vr.Mode != "random" && vr.Mode != "sequential" {
			errs = append(errs, fmt.Sprintf("vpn_rotation %q: mode must be random|sequential", vr.Name))
		}
	}
	for i, r := range c.Rules {
		if r.Name == "" {
			errs = append(errs, fmt.Sprintf("rules[%d]: name is required", i))
		}
		switch r.Action {
		case ActionDirect, ActionBlock, ActionIntercept:
		case ActionProxy:
			if c.ProxyByName(r.Proxy) == nil && !(c.Caido.Enabled && r.Proxy == c.Caido.ProxyName) {
				errs = append(errs, fmt.Sprintf("rule %q: unknown proxy %q", r.Name, r.Proxy))
			}
		case ActionVPN:
			if c.VPNByName(r.VPN) == nil && c.VPNRotationByName(r.VPN) == nil {
				errs = append(errs, fmt.Sprintf("rule %q: unknown vpn %q", r.Name, r.VPN))
			}
		default:
			errs = append(errs, fmt.Sprintf("rule %q: unknown action %q", r.Name, r.Action))
		}
		for _, p := range r.Ports {
			if _, _, err := ParsePortRange(p); err != nil {
				errs = append(errs, fmt.Sprintf("rule %q: %v", r.Name, err))
			}
		}
	}
	if c.Proxifier.MarkBase == 0 || c.Proxifier.MarkBase&0xff != 0 {
		errs = append(errs, "proxifier.mark_base must be non-zero and 256-aligned (e.g. 0x7400)")
	}
	if c.Intercept.Enabled && c.Intercept.Listen != "" {
		if _, _, err := net.SplitHostPort(c.Intercept.Listen); err != nil {
			errs = append(errs, fmt.Sprintf("intercept.listen: bad address %q", c.Intercept.Listen))
		}
	}
	switch c.Intercept.Upstream.Action {
	case ActionDirect, "":
	case ActionProxy:
		if c.ProxyByName(c.Intercept.Upstream.Proxy) == nil && !(c.Caido.Enabled && c.Intercept.Upstream.Proxy == c.Caido.ProxyName) {
			errs = append(errs, fmt.Sprintf("intercept.upstream: unknown proxy %q", c.Intercept.Upstream.Proxy))
		}
	case ActionVPN:
		if c.VPNByName(c.Intercept.Upstream.VPN) == nil && c.VPNRotationByName(c.Intercept.Upstream.VPN) == nil {
			errs = append(errs, fmt.Sprintf("intercept.upstream: unknown vpn %q", c.Intercept.Upstream.VPN))
		}
	default:
		errs = append(errs, fmt.Sprintf("intercept.upstream: bad action %q", c.Intercept.Upstream.Action))
	}
	if c.Intercept.MaxFlows <= 0 {
		c.Intercept.MaxFlows = 10000
	}
	if c.Intercept.MaxBody <= 0 {
		c.Intercept.MaxBody = 1 << 20
	}
	if c.Intercept.CADir == "" {
		c.Intercept.CADir = "/etc/cyberboba/ca"
	}
	if c.Intercept.SessionDir == "" {
		c.Intercept.SessionDir = "/var/lib/cyberboba/sessions"
	}
	for i, w := range c.Intercept.Rewrites {
		if w.Target != "request" && w.Target != "response" {
			errs = append(errs, fmt.Sprintf("intercept.rewrites[%d]: target must be request|response", i))
		}
		if w.Part != "header" && w.Part != "body" && w.Part != "url" {
			errs = append(errs, fmt.Sprintf("intercept.rewrites[%d]: part must be header|body|url", i))
		}
		if w.Part == "header" && w.Header == "" {
			errs = append(errs, fmt.Sprintf("intercept.rewrites[%d]: header name required", i))
		}
		if w.Match != "" {
			if _, err := regexpCompile(w.Match); err != nil {
				errs = append(errs, fmt.Sprintf("intercept.rewrites[%d]: bad match regex: %v", i, err))
			}
		}
	}
	if c.Caido.Enabled {
		if _, _, err := net.SplitHostPort(c.Caido.Listen); err != nil {
			errs = append(errs, fmt.Sprintf("caido.listen: bad address %q", c.Caido.Listen))
		}
		if c.Caido.ProxyName == "" {
			c.Caido.ProxyName = "caido"
		}
	}
	{
		perm := map[string]bool{"": true, "allow": true, "block": true, "ask": true}
		if c.Firewall.Mode == "" {
			c.Firewall.Mode = "ask"
		}
		switch c.Firewall.Mode {
		case "off", "ask", "auto", "block":
		default:
			errs = append(errs, fmt.Sprintf("firewall.mode must be off|ask|auto|block, got %q", c.Firewall.Mode))
		}
		if c.Firewall.AskTimeoutAction == "" {
			c.Firewall.AskTimeoutAction = "block"
		}
		if c.Firewall.AskTimeoutAction != "allow" && c.Firewall.AskTimeoutAction != "block" {
			errs = append(errs, "firewall.ask_timeout_action must be allow|block")
		}
		for i, p := range c.Firewall.Programs {
			if p.App == "" {
				errs = append(errs, fmt.Sprintf("firewall.programs[%d]: app is required", i))
			}
			if !perm[p.Trusted] {
				errs = append(errs, fmt.Sprintf("firewall.programs[%d]: trusted must be allow|block|ask", i))
			}
			if !perm[p.Internet] {
				errs = append(errs, fmt.Sprintf("firewall.programs[%d]: internet must be allow|block|ask", i))
			}
			if p.Server != "" && p.Server != "allow" && p.Server != "block" {
				errs = append(errs, fmt.Sprintf("firewall.programs[%d]: server must be allow|block", i))
			}
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return errors.New("config: " + strings.Join(errs, "; "))
	}
	return nil
}

// ParsePortRange parses "443" or "8000-8100".
func ParsePortRange(s string) (lo, hi int, err error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return 1, 65535, nil
	}
	parts := strings.SplitN(s, "-", 2)
	parse := func(x string) (int, error) {
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(x), "%d", &n); err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("bad port %q", x)
		}
		return n, nil
	}
	if lo, err = parse(parts[0]); err != nil {
		return
	}
	hi = lo
	if len(parts) == 2 {
		if hi, err = parse(parts[1]); err != nil {
			return
		}
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("bad port range %q", s)
	}
	return
}

// Store is a thread-safe holder of the live configuration with change
// notification.
type Store struct {
	mu   sync.RWMutex
	path string
	cfg  *Config
	subs []func(*Config)
}

// NewStore wraps a configuration loaded from path.
func NewStore(path string, cfg *Config) *Store { return &Store{path: path, cfg: cfg} }

// Get returns the current configuration (treat as read-only).
func (s *Store) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Path returns the backing file.
func (s *Store) Path() string { return s.path }

// Subscribe registers a callback invoked after every successful Update.
func (s *Store) Subscribe(fn func(*Config)) {
	s.mu.Lock()
	s.subs = append(s.subs, fn)
	s.mu.Unlock()
}

// Update validates, persists and publishes a new configuration.
func (s *Store) Update(c *Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if s.path != "" {
		if err := c.Save(s.path); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.cfg = c
	subs := append([]func(*Config){}, s.subs...)
	s.mu.Unlock()
	for _, fn := range subs {
		fn(c)
	}
	return nil
}

// Mutate applies fn to a deep copy of the configuration and stores it.
func (s *Store) Mutate(fn func(*Config) error) error {
	cur := s.Get()
	data, err := yaml.Marshal(cur)
	if err != nil {
		return err
	}
	cp := Default()
	cp.Rules = nil
	if err := yaml.Unmarshal(data, cp); err != nil {
		return err
	}
	if err := fn(cp); err != nil {
		return err
	}
	return s.Update(cp)
}

func regexpCompile(p string) (*regexp.Regexp, error) { return regexp.Compile(p) }
