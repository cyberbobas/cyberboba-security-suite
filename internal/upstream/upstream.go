// Package upstream dials destinations directly, through selective VPN
// routing tables, or through SOCKS5/HTTP proxy chains.
package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"cyberboba/internal/config"
)

// Route tells the dialer how to reach a destination.
type Route struct {
	Action config.Action
	Proxy  string // proxy or chain name when Action == proxy
	VPN    string // vpn profile name when Action == vpn
}

// VPNMarker resolves a VPN profile to the fwmark that routes through it.
// ok=false means the VPN is not up or is in full mode (so the default route
// already goes through it).
type VPNMarker func(name string) (mark uint32, ok bool, err error)

// Dialer implements the connection strategy.
type Dialer struct {
	mu        sync.RWMutex
	cfg       *config.Config
	vpnMark   VPNMarker
	Timeout   time.Duration
	markWarn  sync.Once
	warnFn    func(string)
	extraProx map[string]config.Proxy // synthesized entries (e.g. caido)
	rot       map[string]*rotState    // per rotate-group live state
	rotMu     sync.Mutex
}

// rotState tracks the active member of a "rotate" proxy group.
type rotState struct {
	idx  int
	last time.Time
}

// New creates a Dialer.
func New(cfg *config.Config, vm VPNMarker, warn func(string)) *Dialer {
	if warn == nil {
		warn = func(string) {}
	}
	return &Dialer{cfg: cfg, vpnMark: vm, Timeout: 20 * time.Second, warnFn: warn, extraProx: map[string]config.Proxy{}, rot: map[string]*rotState{}}
}

// SetConfig swaps the configuration.
func (d *Dialer) SetConfig(cfg *config.Config) {
	d.mu.Lock()
	d.cfg = cfg
	d.mu.Unlock()
}

// SetExtraProxy registers a proxy not present in the config (Caido).
func (d *Dialer) SetExtraProxy(p config.Proxy) {
	d.mu.Lock()
	d.extraProx[p.Name] = p
	d.mu.Unlock()
}

// RemoveExtraProxy unregisters a synthesized proxy.
func (d *Dialer) RemoveExtraProxy(name string) {
	d.mu.Lock()
	delete(d.extraProx, name)
	d.mu.Unlock()
}

// Proxy looks up a proxy by name including synthesized entries.
func (d *Dialer) Proxy(name string) *config.Proxy {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if p := d.cfg.ProxyByName(name); p != nil {
		return p
	}
	if p, ok := d.extraProx[name]; ok {
		return &p
	}
	return nil
}

// Hops expands a proxy name into the concrete list of proxies to traverse.
func (d *Dialer) Hops(name string) ([]config.Proxy, error) {
	p := d.Proxy(name)
	if p == nil {
		return nil, fmt.Errorf("unknown proxy %q", name)
	}
	if p.Type != config.ProxyChain && p.Type != config.ProxyFailover && p.Type != config.ProxyBalance && p.Type != config.ProxyRotate {
		return []config.Proxy{*p}, nil
	}
	if p.Type == config.ProxyFailover || p.Type == config.ProxyBalance || p.Type == config.ProxyRotate {
		// Groups are expanded at dial time; report the members here.
		var members []config.Proxy
		for _, h := range p.Hops {
			if hp := d.Proxy(h); hp != nil {
				members = append(members, *hp)
			}
		}
		return members, nil
	}
	var hops []config.Proxy
	for _, h := range p.Hops {
		hp := d.Proxy(h)
		if hp == nil {
			return nil, fmt.Errorf("chain %q: unknown hop %q", name, h)
		}
		if hp.Type == config.ProxyChain {
			return nil, fmt.Errorf("chain %q: nested chain %q", name, h)
		}
		hops = append(hops, *hp)
	}
	if len(hops) == 0 {
		return nil, fmt.Errorf("chain %q is empty", name)
	}
	// via_vpn of the chain applies to the first hop.
	if p.ViaVPN != "" && hops[0].ViaVPN == "" {
		hops[0].ViaVPN = p.ViaVPN
	}
	return hops, nil
}

// Target is the destination of a dial.
type Target struct {
	Host string // optional hostname
	IP   netip.Addr
	Port int
}

func (t Target) hostPort(preferHost bool) string {
	if (preferHost || !t.IP.IsValid()) && t.Host != "" {
		return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	}
	return netip.AddrPortFrom(t.IP.Unmap(), uint16(t.Port)).String()
}

// Dial connects to the target according to the route.
func (d *Dialer) Dial(ctx context.Context, r Route, t Target) (net.Conn, string, error) {
	switch r.Action {
	case config.ActionBlock:
		return nil, "", errors.New("blocked by rule")
	case config.ActionDirect, "":
		c, err := d.dialMarked(ctx, d.bypassMark(), t.hostPort(false))
		return c, "", err
	case config.ActionVPN:
		mark, err := d.markForVPN(r.VPN)
		if err != nil {
			return nil, "", err
		}
		c, err := d.dialMarked(ctx, mark, t.hostPort(false))
		return c, r.VPN, err
	case config.ActionProxy:
		p := d.Proxy(r.Proxy)
		if p == nil {
			return nil, "", fmt.Errorf("unknown proxy %q", r.Proxy)
		}
		if p.Type == config.ProxyFailover || p.Type == config.ProxyBalance || p.Type == config.ProxyRotate {
			return d.dialGroup(ctx, p, t)
		}
		hops, err := d.Hops(r.Proxy)
		if err != nil {
			return nil, "", err
		}
		c, err := d.dialChain(ctx, hops, t)
		return c, r.Proxy, err
	}
	return nil, "", fmt.Errorf("unknown action %q", r.Action)
}

// dialGroup implements failover (in order) and balance (random start)
// groups of proxies.
func (d *Dialer) dialGroup(ctx context.Context, g *config.Proxy, t Target) (net.Conn, string, error) {
	names := append([]string(nil), g.Hops...)
	if len(names) == 0 {
		return nil, "", fmt.Errorf("proxy group %q is empty", g.Name)
	}
	if g.Type == config.ProxyBalance {
		off := int(time.Now().UnixNano() % int64(len(names)))
		names = append(names[off:], names[:off]...)
	}
	if g.Type == config.ProxyRotate {
		cur := d.rotPick(g, false)
		// try the current member first, then the rest as failover fallback.
		ordered := []string{names[cur]}
		for i, n := range names {
			if i != cur {
				ordered = append(ordered, n)
			}
		}
		names = ordered
	}
	var lastErr error
	for _, n := range names {
		hops, err := d.Hops(n)
		if err != nil {
			lastErr = err
			continue
		}
		if g.ViaVPN != "" && hops[0].ViaVPN == "" {
			hops[0].ViaVPN = g.ViaVPN
		}
		c, err := d.dialChain(ctx, hops, t)
		if err == nil {
			return c, g.Name + "/" + n, nil
		}
		lastErr = err
		d.warnFn(fmt.Sprintf("proxy group %s: member %s failed: %v", g.Name, n, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, "", fmt.Errorf("all members of %q failed: %w", g.Name, lastErr)
}

// rotPick returns the index of the active member for a rotate group, advancing
// to a new member when the interval has elapsed (or when forced). Random mode
// avoids repeating the same member; sequential advances in order.
func (d *Dialer) rotPick(g *config.Proxy, force bool) int {
	n := len(g.Hops)
	if n == 0 {
		return 0
	}
	every := time.Duration(g.RotateEverySec) * time.Second
	if every <= 0 {
		every = 300 * time.Second
	}
	d.rotMu.Lock()
	defer d.rotMu.Unlock()
	st := d.rot[g.Name]
	now := time.Now()
	if st == nil {
		st = &rotState{idx: int(now.UnixNano()) % n, last: now}
		if st.idx < 0 {
			st.idx = 0
		}
		d.rot[g.Name] = st
		return st.idx
	}
	if st.idx >= n {
		st.idx = 0
	}
	if force || now.Sub(st.last) >= every {
		st.idx = d.nextIdx(g, st.idx, n)
		st.last = now
	}
	return st.idx
}

func (d *Dialer) nextIdx(g *config.Proxy, cur, n int) int {
	if n <= 1 {
		return 0
	}
	if g.RotateMode == "sequential" {
		return (cur + 1) % n
	}
	// random, different from current
	for i := 0; i < 8; i++ {
		j := int(time.Now().UnixNano()>>uint(i)) % n
		if j < 0 {
			j = -j
		}
		if j != cur {
			return j
		}
	}
	return (cur + 1) % n
}

// TickRotations advances rotate groups whose interval elapsed. Returns the
// groups that switched member as "name=member" for event emission.
func (d *Dialer) TickRotations() []RotationChange {
	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()
	var changed []RotationChange
	now := time.Now()
	for i := range cfg.Proxies {
		g := &cfg.Proxies[i]
		if g.Type != config.ProxyRotate || len(g.Hops) == 0 {
			continue
		}
		every := time.Duration(g.RotateEverySec) * time.Second
		if every <= 0 {
			every = 300 * time.Second
		}
		d.rotMu.Lock()
		st := d.rot[g.Name]
		due := st == nil || now.Sub(st.last) >= every
		d.rotMu.Unlock()
		if due {
			before := -1
			if st != nil {
				before = st.idx
			}
			idx := d.rotPick(g, st != nil) // force advance if already seeded
			if idx != before && idx < len(g.Hops) {
				changed = append(changed, RotationChange{Group: g.Name, Member: g.Hops[idx]})
			}
		}
	}
	return changed
}

// RotationChange reports a rotate group switching to a new active member.
type RotationChange struct {
	Group  string `json:"group"`
	Member string `json:"member"`
}

// RotationStatus is the live view of one rotate group.
type RotationStatus struct {
	Name      string   `json:"name"`
	Current   string   `json:"current"`
	Members   []string `json:"members"`
	EverySec  int      `json:"every_sec"`
	Mode      string   `json:"mode"`
	NextInSec int      `json:"next_in_sec"`
}

// RotationStates returns the live state of every rotate group.
func (d *Dialer) RotationStates() []RotationStatus {
	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()
	var out []RotationStatus
	now := time.Now()
	for i := range cfg.Proxies {
		g := &cfg.Proxies[i]
		if g.Type != config.ProxyRotate {
			continue
		}
		every := g.RotateEverySec
		if every <= 0 {
			every = 300
		}
		rs := RotationStatus{Name: g.Name, Members: append([]string(nil), g.Hops...), EverySec: every, Mode: g.RotateMode}
		d.rotMu.Lock()
		st := d.rot[g.Name]
		if st != nil && st.idx < len(g.Hops) {
			rs.Current = g.Hops[st.idx]
			rs.NextInSec = every - int(now.Sub(st.last).Seconds())
			if rs.NextInSec < 0 {
				rs.NextInSec = 0
			}
		} else if len(g.Hops) > 0 {
			rs.Current = g.Hops[0]
			rs.NextInSec = every
		}
		d.rotMu.Unlock()
		out = append(out, rs)
	}
	return out
}

func (d *Dialer) bypassMark() uint32 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cfg.BypassMark()
}

func (d *Dialer) markForVPN(name string) (uint32, error) {
	if d.vpnMark == nil {
		return d.bypassMark(), nil
	}
	mark, ok, err := d.vpnMark(name)
	if err != nil {
		return 0, err
	}
	if !ok {
		return d.bypassMark(), nil
	}
	return mark, nil
}

// dialMarked opens a TCP connection with SO_MARK set so netfilter does not
// redirect it and policy routing can steer it.
func (d *Dialer) dialMarked(ctx context.Context, mark uint32, addr string) (net.Conn, error) {
	nd := net.Dialer{Timeout: d.Timeout}
	nd.Control = markControl(mark, func(err error) {
		d.markWarn.Do(func() {
			d.warnFn("cannot set SO_MARK (need CAP_NET_ADMIN): " + err.Error() + "; outbound sockets are unmarked")
		})
	})
	return nd.DialContext(ctx, "tcp", addr)
}

// dialChain connects through hops[0] -> hops[1] -> ... -> target.
func (d *Dialer) dialChain(ctx context.Context, hops []config.Proxy, t Target) (net.Conn, error) {
	first := hops[0]
	mark := d.bypassMark()
	if first.ViaVPN != "" {
		m, err := d.markForVPN(first.ViaVPN)
		if err != nil {
			return nil, err
		}
		mark = m
	}
	conn, err := d.dialMarked(ctx, mark, first.Addr)
	if err != nil {
		return nil, fmt.Errorf("proxy %s (%s): %w", first.Name, first.Addr, err)
	}
	deadline := time.Now().Add(d.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	for i := range hops {
		hop := hops[i]
		var next string
		if i+1 < len(hops) {
			next = hops[i+1].Addr
		} else {
			next = t.hostPort(hop.RemoteDNS)
		}
		if err := handshake(conn, hop, next); err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy %s: %w", hop.Name, err)
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func handshake(conn net.Conn, p config.Proxy, target string) error {
	switch p.Type {
	case config.ProxySOCKS5:
		return socks5Connect(conn, p.Username, p.Password, target)
	case config.ProxyHTTP:
		return httpConnect(conn, p.Username, p.Password, target)
	case config.ProxySOCKS4:
		return socks4Connect(conn, p.Username, target)
	}
	return fmt.Errorf("unsupported proxy type %q", p.Type)
}

// socks4Connect performs a SOCKS4 (or SOCKS4a for hostnames) CONNECT.
func socks4Connect(conn net.Conn, userID, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x04, 0x01, byte(port >> 8), byte(port)}
	ip, err := netip.ParseAddr(host)
	useA := err != nil || !ip.Unmap().Is4()
	if useA {
		req = append(req, 0, 0, 0, 1)
	} else {
		b := ip.Unmap().As4()
		req = append(req, b[:]...)
	}
	req = append(req, userID...)
	req = append(req, 0)
	if useA {
		req = append(req, host...)
		req = append(req, 0)
	}
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var resp [8]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}
	if resp[1] != 0x5a {
		return fmt.Errorf("SOCKS4 connect failed: code 0x%02x", resp[1])
	}
	return nil
}

// socks5Connect performs RFC 1928/1929 negotiation and CONNECT.
func socks5Connect(conn net.Conn, user, pass, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(portStr)
	methods := []byte{0x00}
	if user != "" {
		methods = append(methods, 0x02)
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return errors.New("not a SOCKS5 server")
	}
	switch resp[1] {
	case 0x00:
	case 0x02:
		if user == "" {
			return errors.New("proxy requires authentication")
		}
		buf := []byte{0x01, byte(len(user))}
		buf = append(buf, user...)
		buf = append(buf, byte(len(pass)))
		buf = append(buf, pass...)
		if _, err := conn.Write(buf); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, resp[:]); err != nil {
			return err
		}
		if resp[1] != 0x00 {
			return errors.New("proxy authentication failed")
		}
	default:
		return fmt.Errorf("no acceptable auth method (0x%02x)", resp[1])
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b := ip.As4()
			req = append(req, 0x01)
			req = append(req, b[:]...)
		} else {
			b := ip.As16()
			req = append(req, 0x04)
			req = append(req, b[:]...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed: %s", socksError(hdr[1]))
	}
	var skip int
	switch hdr[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		skip = int(l[0]) + 2
	default:
		return errors.New("bad SOCKS5 reply")
	}
	_, err = io.CopyN(io.Discard, conn, int64(skip))
	return err
}

func socksError(c byte) string {
	switch c {
	case 1:
		return "general failure"
	case 2:
		return "connection not allowed by ruleset"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "TTL expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	}
	return fmt.Sprintf("code %d", c)
}

// httpConnect issues an HTTP CONNECT request.
func httpConnect(conn net.Conn, user, pass, target string) error {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n", target, target)
	if user != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("CONNECT %s: %s", target, resp.Status)
	}
	if br.Buffered() > 0 {
		// Unlikely: server data before we sent anything. Preserve it.
		return errors.New("unexpected data after CONNECT response")
	}
	return nil
}

// VPNMark exposes the mark used for a VPN profile (ok=false when the
// default route should be used).
func (d *Dialer) VPNMark(name string) (uint32, bool, error) {
	if d.vpnMark == nil {
		return 0, false, nil
	}
	return d.vpnMark(name)
}
