// Package proxy is the transparent TCP interception engine: it accepts
// REDIRECTed connections, identifies the owning process, classifies the
// connection with the rule engine and relays it to the chosen upstream.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"cyberboba/internal/config"
	"cyberboba/internal/firewall"
	"cyberboba/internal/procinfo"
	"cyberboba/internal/rules"
	"cyberboba/internal/stats"
	"cyberboba/internal/upstream"
)

// HostLookup resolves an IP back to the hostname an application asked for.
type HostLookup func(ip netip.Addr) string

// Interceptor receives connections whose rule action is "intercept".
type Interceptor interface {
	HandleConn(c net.Conn, head []byte, host string, ip netip.Addr, port int, app string, pid int)
}

// Engine is the transparent proxy.
type Engine struct {
	mu        sync.RWMutex
	cfg       *config.Config
	rules     *rules.Engine
	dialer    *upstream.Dialer
	procs     *procinfo.Resolver
	tracker   *stats.Tracker
	hostOf    HostLookup
	listeners []net.Listener
	logf      func(level, format string, args ...interface{})
	loopPIDs  map[string]pidCache
	wg        sync.WaitGroup
	closed    chan struct{}
	sniff     bool
	intercept Interceptor
	firewall  *firewall.Engine
}

type pidCache struct {
	pid int
	at  time.Time
}

// New creates an Engine.
func New(cfg *config.Config, d *upstream.Dialer, p *procinfo.Resolver, t *stats.Tracker, hostOf HostLookup,
	logf func(level, format string, args ...interface{})) *Engine {
	if logf == nil {
		logf = func(string, string, ...interface{}) {}
	}
	if hostOf == nil {
		hostOf = func(netip.Addr) string { return "" }
	}
	e := &Engine{dialer: d, procs: p, tracker: t, hostOf: hostOf, logf: logf, loopPIDs: map[string]pidCache{}, closed: make(chan struct{})}
	e.SetConfig(cfg)
	return e
}

// SetConfig recompiles rules.
func (e *Engine) SetConfig(cfg *config.Config) {
	e.mu.Lock()
	e.cfg = cfg
	e.rules = rules.Compile(cfg.Rules)
	e.sniff = cfg.Proxifier.SniffHostnames
	e.mu.Unlock()
}

// SetInterceptor registers the intercepting proxy.
func (e *Engine) SetInterceptor(i Interceptor) {
	e.mu.Lock()
	e.intercept = i
	e.mu.Unlock()
}

// SetFirewall registers the application firewall (ZoneAlarm-style gate).
func (e *Engine) SetFirewall(fw *firewall.Engine) {
	e.mu.Lock()
	e.firewall = fw
	e.mu.Unlock()
}

// Evaluate exposes the rule engine (used by the API tester).
func (e *Engine) Evaluate(c rules.Conn) rules.Decision {
	e.mu.RLock()
	r := e.rules
	e.mu.RUnlock()
	return r.Evaluate(c)
}

// Start opens the listeners. addr is "127.0.0.1:7470"; the IPv6 twin
// "[::1]:port" is opened too when v6 is set.
func (e *Engine) Start(addr string, v6 bool) error {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	e.listeners = append(e.listeners, ln)
	if v6 {
		_, port, _ := net.SplitHostPort(addr)
		ln6, err := net.Listen("tcp6", net.JoinHostPort("::1", port))
		if err != nil {
			e.logf("warn", "ipv6 listener: %v", err)
		} else {
			e.listeners = append(e.listeners, ln6)
		}
	}
	for _, l := range e.listeners {
		e.wg.Add(1)
		go e.acceptLoop(l)
	}
	return nil
}

// Stop closes listeners; in-flight connections keep running.
func (e *Engine) Stop() {
	close(e.closed)
	for _, l := range e.listeners {
		l.Close()
	}
	e.wg.Wait()
}

func (e *Engine) acceptLoop(l net.Listener) {
	defer e.wg.Done()
	for {
		c, err := l.Accept()
		if err != nil {
			select {
			case <-e.closed:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			e.logf("error", "accept: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go e.handle(c)
	}
}

// serverFirstPorts are protocols where the server speaks first; sniffing
// would only add latency there.
var serverFirstPorts = map[int]bool{21: true, 22: true, 25: true, 110: true, 143: true, 465: false, 587: true, 993: false, 995: false, 3306: true, 5432: false, 6667: true}

func (e *Engine) handle(client net.Conn) {
	tc, ok := client.(*net.TCPConn)
	if !ok {
		client.Close()
		return
	}
	dst, err := originalDst(tc)
	if err != nil {
		e.logf("debug", "no original destination for %s: %v (not redirected?)", client.RemoteAddr(), err)
		client.Close()
		return
	}
	src := netip.MustParseAddrPort(client.RemoteAddr().String())
	e.serve(client, src, dst, dst, "", true)
}

// guessApp names the program that most recently had a *resolved* connection
// to the same destination (same uid when known). Used only to label a
// firewall prompt whose process could not be resolved; never for rules.
func (e *Engine) guessApp(host string, ip netip.Addr, uid int) string {
	if e.tracker == nil || (host == "" && !ip.IsValid()) {
		return ""
	}
	dst := ""
	if ip.IsValid() {
		dst = ip.String()
	}
	conns := e.tracker.List(0, true)
	for i := len(conns) - 1; i >= 0; i-- {
		c := &conns[i]
		if c.App == "" || c.PID == os.Getpid() {
			continue
		}
		if !((host != "" && c.Host == host) || (dst != "" && c.DstIP == dst)) {
			continue
		}
		if uid >= 0 && c.User != "" && c.User != e.procs.UserName(uid) {
			continue
		}
		return c.App
	}
	return ""
}

// serve classifies and relays one client connection.
//
//	src/lookupDst: the client socket's endpoints as seen in /proc/net/tcp
//	dst: the real destination
//	host: destination hostname if already known (SOCKS5 domain request)
//	sniff: whether to peek the first bytes for SNI / Host
func (e *Engine) serve(client net.Conn, src, lookupDst, dst netip.AddrPort, host string, sniff bool) {
	e.serveWithHead(client, src, lookupDst, dst, host, nil)
}

// serveWithHead is serve() with bytes that were already read from the client
// (they are sniffed and forwarded first). When head is nil the first bytes
// are peeked here.
func (e *Engine) serveWithHead(client net.Conn, src, lookupDst, dst netip.AddrPort, host string, head []byte) {
	sniff := head == nil
	rc := rules.Conn{IP: dst.Addr().Unmap(), Port: int(dst.Port()), Proto: "tcp", UID: -1}
	tracked := &stats.Conn{Proto: "tcp", DstPort: rc.Port, PID: -1}
	if rc.IP.IsValid() {
		tracked.DstIP = rc.IP.String()
	}
	// The owning process is looked up right after the kernel completed the
	// handshake on our side; the client's fd table may still be settling,
	// so retry a few times before giving up.
	// The socket cannot vanish while the client keeps the connection open, so a
	// longer back-off (≈0.6 s total) is cheap insurance against a /proc scan
	// racing a busy fd table (Chromium, Electron, Bun); the firewall would
	// otherwise prompt for an "(unknown program)".
	var lookupErr error
	lookupDelays := []time.Duration{10, 20, 40, 80, 150, 300}
	var hints []netip.AddrPort
	if ap, err := netip.ParseAddrPort(client.LocalAddr().String()); err == nil {
		hints = []netip.AddrPort{ap}
	}
	for attempt := 0; attempt < len(lookupDelays); attempt++ {
		p, uid, err := e.procs.Lookup(src, lookupDst, hints...)
		if err == nil {
			name := p.DisplayName()
			rc.App, rc.Exe, rc.Cmd, rc.Tag, rc.UID, rc.User = name, p.Exe, p.Cmd, p.Tag, p.UID, p.User
			tracked.PID, tracked.App, tracked.Exe, tracked.User, tracked.Tag = p.PID, name, p.Exe, p.User, p.Tag
			if attempt > 0 {
				e.logf("debug", "process lookup %v->%v succeeded on attempt %d (%s)", src, lookupDst, attempt+1, name)
			}
			lookupErr = nil
			break
		}
		lookupErr = err
		if uid >= 0 {
			rc.UID = uid
		}
		time.Sleep(lookupDelays[attempt] * time.Millisecond)
	}
	if lookupErr != nil {
		e.logf("warn", "process lookup %v->%v failed (uid %d): %v", src, lookupDst, rc.UID, lookupErr)
		if rc.UID >= 0 && rc.User == "" {
			rc.User = e.procs.UserName(rc.UID)
			tracked.User = rc.User
		}
	}
	rc.Host = host
	if rc.Host == "" && rc.IP.IsValid() {
		rc.Host = e.hostOf(rc.IP)
	}

	// Peek the first bytes for SNI / Host.
	e.mu.RLock()
	sniffOn := e.sniff
	e.mu.RUnlock()
	if sniff && sniffOn && !serverFirstPorts[rc.Port] {
		buf := make([]byte, 4096)
		_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := client.Read(buf)
		_ = client.SetReadDeadline(time.Time{})
		head = buf[:n]
	}
	if sniffOn && len(head) > 0 {
		if h := sniffHost(head); h != "" {
			rc.Host = h
		}
	}
	tracked.Host = rc.Host
	// Label-only guess for an unresolved process, now that the hostname is known.
	appGuess := ""
	if lookupErr != nil {
		appGuess = e.guessApp(rc.Host, rc.IP, rc.UID)
	}

	d := e.Evaluate(rc)
	// SOCKS clients may hand us only a hostname. Resolve it lazily: only
	// when the chosen route needs an IP (direct/vpn, or a proxy that does
	// not resolve remotely), then re-evaluate so CIDR rules still apply.
	if !rc.IP.IsValid() && rc.Host != "" && e.needsIP(d) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", rc.Host)
		cancel()
		if err == nil && len(ips) > 0 {
			rc.IP = ips[0].Unmap()
			for _, a := range ips {
				if a.Unmap().Is4() {
					rc.IP = a.Unmap()
					break
				}
			}
			tracked.DstIP = rc.IP.String()
			d = e.Evaluate(rc)
		} else {
			e.logf("debug", "resolve %s: %v", rc.Host, err)
		}
	}
	if d.Matched {
		tracked.Rule = d.Rule.Name
	} else {
		tracked.Rule = "(no match)"
	}
	route := upstream.Route{Action: d.Action, Proxy: d.Proxy, VPN: d.VPN}
	tracked.Action = string(d.Action)
	tracked.Via = d.Proxy
	tracked.VPN = d.VPN

	// Loop protection: a proxy's own outbound traffic must not be sent back
	// into itself.
	if route.Action == config.ActionProxy && tracked.PID > 0 && e.isProxyProcess(route.Proxy, tracked.PID) {
		route = upstream.Route{Action: config.ActionDirect}
		tracked.Action = "direct"
		tracked.Via = ""
		tracked.Rule += " (loop guard)"
	}

	// Application firewall (ZoneAlarm-style): decide whether this program may
	// reach the network for this zone. "ask" mode holds the connection here.
	e.mu.RLock()
	fw := e.firewall
	e.mu.RUnlock()
	if fw != nil && fw.Active() && tracked.PID != os.Getpid() {
		fd := fw.Check(firewall.Conn{App: tracked.App, Exe: tracked.Exe, Cmd: rc.Cmd, Tag: tracked.Tag, Guess: appGuess,
			IP: rc.IP, Port: rc.Port, Host: rc.Host, PID: tracked.PID, User: tracked.User})
		if !fd.Allow {
			tracked.Action = "block"
			tracked.Via = ""
			tracked.Rule = "firewall: " + fd.Reason
			tracked.State = stats.StateBlocked
			e.tracker.Open(tracked)
			client.Close()
			return
		}
	}

	if route.Action == config.ActionBlock {
		tracked.State = stats.StateBlocked
		e.tracker.Open(tracked)
		client.Close()
		return
	}
	if route.Action == config.ActionIntercept {
		e.mu.RLock()
		ic := e.intercept
		e.mu.RUnlock()
		if ic == nil {
			e.logf("warn", "rule %s: intercept engine disabled, falling back to direct", tracked.Rule)
			route = upstream.Route{Action: config.ActionDirect}
			tracked.Action = "direct"
		} else {
			tracked.Via = "intercept"
			e.tracker.Open(tracked)
			tracked.SetCloser(func() { client.Close() })
			cc := &countConn{Conn: client, t: tracked}
			ic.HandleConn(cc, head, rc.Host, rc.IP, rc.Port, tracked.App, tracked.PID)
			e.tracker.Close(tracked, stats.StateClosed, "")
			return
		}
	}

	e.tracker.Open(tracked)
	tracked.SetCloser(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	up, via, err := e.dialer.Dial(ctx, route, upstream.Target{Host: rc.Host, IP: rc.IP, Port: rc.Port})
	cancel()
	if err != nil {
		e.logf("warn", "%s -> %s:%d via %s: %v", tracked.App, rc.IP, rc.Port, tracked.Action, err)
		e.tracker.Close(tracked, stats.StateError, err.Error())
		client.Close()
		return
	}
	// For proxy groups (rotate/balance/failover) Dial reports the concrete
	// member used (e.g. "rotator/e2"); surface it on the connection.
	if via != "" && via != tracked.Via {
		tracked.Via = via
		e.tracker.Update(tracked)
	}
	tracked.SetCloser(func() { client.Close(); up.Close() })
	if len(head) > 0 {
		if _, err := up.Write(head); err != nil {
			e.tracker.Close(tracked, stats.StateError, err.Error())
			client.Close()
			up.Close()
			return
		}
		tracked.AddOut(int64(len(head)))
	}
	relay(client, up, tracked)
	e.tracker.Close(tracked, stats.StateClosed, "")
}

// needsIP reports whether the decision requires a resolved destination IP.
func (e *Engine) needsIP(d rules.Decision) bool {
	switch d.Action {
	case config.ActionBlock:
		return false
	case config.ActionProxy:
		hops, err := e.dialer.Hops(d.Proxy)
		if err != nil || len(hops) == 0 {
			return false
		}
		return !hops[len(hops)-1].RemoteDNS
	}
	return true
}

// isProxyProcess reports whether pid is the process listening on one of the
// hops of the named proxy.
func (e *Engine) isProxyProcess(proxyName string, pid int) bool {
	hops, err := e.dialer.Hops(proxyName)
	if err != nil {
		return false
	}
	for _, h := range hops {
		ap, err := netip.ParseAddrPort(h.Addr)
		if err != nil {
			host, port, err := net.SplitHostPort(h.Addr)
			if err != nil {
				continue
			}
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				continue
			}
			a, _ := netip.AddrFromSlice(ips[0])
			var p uint16
			fmt.Sscanf(port, "%d", &p)
			ap = netip.AddrPortFrom(a, p)
		}
		if !ap.Addr().IsLoopback() && !ap.Addr().IsUnspecified() && !isLocalAddr(ap.Addr()) {
			continue
		}
		e.mu.Lock()
		pc, ok := e.loopPIDs[h.Addr]
		e.mu.Unlock()
		if !ok || time.Since(pc.at) > 5*time.Second || pc.pid != pid {
			pc = pidCache{pid: e.procs.ListeningPID(ap), at: time.Now()}
			e.mu.Lock()
			e.loopPIDs[h.Addr] = pc
			e.mu.Unlock()
		}
		if pc.pid != 0 && pc.pid == pid {
			return true
		}
	}
	return false
}

var localAddrCache struct {
	sync.Mutex
	at   time.Time
	addr map[netip.Addr]bool
}

func isLocalAddr(a netip.Addr) bool {
	localAddrCache.Lock()
	defer localAddrCache.Unlock()
	if time.Since(localAddrCache.at) > 10*time.Second {
		m := map[netip.Addr]bool{}
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, ad := range addrs {
				if ipn, ok := ad.(*net.IPNet); ok {
					if x, ok := netip.AddrFromSlice(ipn.IP); ok {
						m[x.Unmap()] = true
					}
				}
			}
		}
		localAddrCache.addr = m
		localAddrCache.at = time.Now()
	}
	return localAddrCache.addr[a.Unmap()]
}

// countConn accounts bytes of a connection handed to the interceptor.
type countConn struct {
	net.Conn
	t *stats.Conn
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.t.AddOut(int64(n))
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.t.AddIn(int64(n))
	return n, err
}

// relay copies both directions and accounts bytes.
func relay(client, up net.Conn, t *stats.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := copyCount(up, client, t.AddOut)
		_ = n
		if tc, ok := up.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else {
			up.Close()
		}
	}()
	go func() {
		defer wg.Done()
		copyCount(client, up, t.AddIn)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else {
			client.Close()
		}
	}()
	wg.Wait()
	client.Close()
	up.Close()
}

func copyCount(dst io.Writer, src io.Reader, acct func(int64)) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
			acct(int64(n))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

// originalDst returns the pre-NAT destination of a REDIRECTed connection.
func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var ap netip.AddrPort
	var serr error
	err = raw.Control(func(fd uintptr) {
		ap, serr = getOriginalDst(int(fd), strings.Contains(c.LocalAddr().String(), "["))
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	return ap, serr
}

const soOriginalDst = 80 // SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST

func getOriginalDst(fd int, v6 bool) (netip.AddrPort, error) {
	if !v6 {
		var addr unix.RawSockaddrInet4
		l := uint32(unsafe.Sizeof(addr))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_IP), soOriginalDst,
			uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&l)), 0)
		if errno != 0 {
			return netip.AddrPort{}, errno
		}
		port := (uint16(addr.Port&0xff) << 8) | uint16(addr.Port>>8)
		return netip.AddrPortFrom(netip.AddrFrom4(addr.Addr), port), nil
	}
	var addr unix.RawSockaddrInet6
	l := uint32(unsafe.Sizeof(addr))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_IPV6), soOriginalDst,
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&l)), 0)
	if errno != 0 {
		return netip.AddrPort{}, errno
	}
	port := (uint16(addr.Port&0xff) << 8) | uint16(addr.Port>>8)
	return netip.AddrPortFrom(netip.AddrFrom16(addr.Addr), port), nil
}
