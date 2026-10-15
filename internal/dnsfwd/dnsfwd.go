// Package dnsfwd is a small DNS forwarder. Its job is twofold: route DNS
// queries according to the rule engine (direct / VPN / proxy via DNS-over-TCP)
// and remember which IP addresses belong to which hostnames so that TCP
// connections can be matched against hostname rules.
package dnsfwd

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"cyberboba/internal/config"
	"cyberboba/internal/rules"
	"cyberboba/internal/upstream"
)

// Router decides how a DNS query for name should be sent.
type Router func(name string) upstream.Route

// Forwarder is the DNS listener.
type Forwarder struct {
	mu       sync.RWMutex
	upstream string
	dialer   *upstream.Dialer
	route    Router
	mark     uint32
	logf     func(level, format string, args ...interface{})

	conns  []*net.UDPConn
	tcpLns []net.Listener
	closed chan struct{}

	cacheMu sync.RWMutex
	cache   map[netip.Addr]cacheEntry

	filter *Filter
}

type cacheEntry struct {
	name string
	exp  time.Time
}

// New creates a forwarder.
func New(cfg *config.Config, d *upstream.Dialer, route Router, logf func(level, format string, args ...interface{})) *Forwarder {
	if logf == nil {
		logf = func(string, string, ...interface{}) {}
	}
	f := &Forwarder{dialer: d, route: route, logf: logf, closed: make(chan struct{}), cache: map[netip.Addr]cacheEntry{}}
	f.SetConfig(cfg)
	return f
}

// SetConfig updates upstream and mark.
func (f *Forwarder) SetConfig(cfg *config.Config) {
	f.mu.Lock()
	f.upstream = cfg.Proxifier.DNSUpstream
	f.mark = cfg.BypassMark()
	f.mu.Unlock()
}

// Lookup returns the hostname last resolved to ip, if any.
func (f *Forwarder) Lookup(ip netip.Addr) string {
	f.cacheMu.RLock()
	e, ok := f.cache[ip.Unmap()]
	f.cacheMu.RUnlock()
	if !ok || time.Now().After(e.exp) {
		return ""
	}
	return e.name
}

// Remember stores an ip->name mapping (also used by the SNI sniffer).
func (f *Forwarder) Remember(ip netip.Addr, name string, ttl time.Duration) {
	if ttl < 10*time.Minute {
		ttl = 10 * time.Minute
	}
	f.cacheMu.Lock()
	f.cache[ip.Unmap()] = cacheEntry{name: strings.ToLower(strings.TrimSuffix(name, ".")), exp: time.Now().Add(ttl)}
	if len(f.cache) > 50000 {
		now := time.Now()
		for k, v := range f.cache {
			if now.After(v.exp) {
				delete(f.cache, k)
			}
		}
	}
	f.cacheMu.Unlock()
}

// Start listens on addr (UDP and TCP) and on the IPv6 loopback twin.
func (f *Forwarder) Start(addr string, v6 bool) error {
	addrs := []string{addr}
	if v6 {
		_, port, _ := net.SplitHostPort(addr)
		addrs = append(addrs, net.JoinHostPort("::1", port))
	}
	for i, a := range addrs {
		ua, err := net.ResolveUDPAddr("udp", a)
		if err != nil {
			return err
		}
		uc, err := net.ListenUDP("udp", ua)
		if err != nil {
			if i > 0 {
				f.logf("warn", "dns ipv6 listener: %v", err)
				continue
			}
			return err
		}
		f.conns = append(f.conns, uc)
		go f.serveUDP(uc)
		ln, err := net.Listen("tcp", a)
		if err == nil {
			f.tcpLns = append(f.tcpLns, ln)
			go f.serveTCP(ln)
		}
	}
	return nil
}

// Stop closes the listeners.
func (f *Forwarder) Stop() {
	close(f.closed)
	for _, c := range f.conns {
		c.Close()
	}
	for _, l := range f.tcpLns {
		l.Close()
	}
}

func (f *Forwarder) serveUDP(uc *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, from, err := uc.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-f.closed:
				return
			default:
				continue
			}
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		go func() {
			resp, err := f.Resolve(q)
			if err != nil {
				f.logf("debug", "dns: %v", err)
				resp = servfail(q)
			}
			if resp != nil {
				uc.WriteToUDP(resp, from)
			}
		}()
	}
}

func (f *Forwarder) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			for {
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp, err := f.Resolve(q)
				if err != nil {
					resp = servfail(q)
				}
				if resp == nil {
					return
				}
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				copy(out[2:], resp)
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}()
	}
}

func servfail(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	r := make([]byte, 12)
	copy(r, q[:12])
	r[2] = 0x81 // QR + RD
	r[3] = 0x82 // RA + SERVFAIL
	r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11] = 0, 0, 0, 0, 0, 0, 0, 0
	return r
}

// Resolve forwards one query and records answers in the cache.
func (f *Forwarder) Resolve(q []byte) ([]byte, error) {
	name, qtype := questionNameType(q)
	if f.filter != nil && name != "" {
		if blk, reason := f.filter.Blocked(name); blk {
			f.filter.Note(name, qtype, true, reason)
			if f.filter.Sinkhole() == "zero" {
				if r := sinkZero(q); r != nil {
					return r, nil
				}
			}
			return nxdomain(q), nil
		}
		f.filter.Note(name, qtype, false, "")
	}
	route := upstream.Route{Action: config.ActionDirect}
	if f.route != nil && name != "" {
		route = f.route(name)
	}
	f.mu.RLock()
	up, mark := f.upstream, f.mark
	f.mu.RUnlock()

	var resp []byte
	var err error
	switch route.Action {
	case config.ActionBlock:
		return nxdomain(q), nil
	case config.ActionProxy:
		resp, err = f.viaTCP(route, up, q)
	default:
		resp, err = f.viaUDP(route, up, mark, q)
	}
	if err != nil {
		return nil, err
	}
	f.record(resp)
	return resp, nil
}

func (f *Forwarder) viaUDP(route upstream.Route, up string, mark uint32, q []byte) ([]byte, error) {
	m := mark
	if route.Action == config.ActionVPN {
		if vm, ok, err := f.vpnMark(route.VPN); err == nil && ok {
			m = vm
		}
	}
	d := net.Dialer{Timeout: 3 * time.Second, Control: markControl(m)}
	c, err := d.Dial("udp", up)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	if n >= 12 && buf[2]&0x02 != 0 { // truncated: retry over TCP
		if r, err := f.viaTCP(route, up, q); err == nil {
			return r, nil
		}
	}
	return buf[:n], nil
}

func (f *Forwarder) vpnMark(name string) (uint32, bool, error) {
	// The dialer knows; reuse its route logic by dialing nothing. Simplest:
	// expose through a tiny helper on the dialer.
	return f.dialer.VPNMark(name)
}

func (f *Forwarder) viaTCP(route upstream.Route, up string, q []byte) ([]byte, error) {
	ap, err := netip.ParseAddrPort(up)
	if err != nil {
		host, port, e := net.SplitHostPort(up)
		if e != nil {
			return nil, e
		}
		ips, e := net.LookupIP(host)
		if e != nil || len(ips) == 0 {
			return nil, errors.New("cannot resolve dns upstream " + host)
		}
		a, _ := netip.AddrFromSlice(ips[0])
		var p int
		for _, ch := range port {
			p = p*10 + int(ch-'0')
		}
		ap = netip.AddrPortFrom(a, uint16(p))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, _, err := f.dialer.Dial(ctx, route, upstream.Target{IP: ap.Addr(), Port: int(ap.Port())})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	out := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(out, uint16(len(q)))
	copy(out[2:], q)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// Filter returns the DNS block filter (may be nil).
func (f *Forwarder) Filter() *Filter { return f.filter }

// SetFilter attaches a block filter.
func (f *Forwarder) SetFilter(flt *Filter) { f.filter = flt }

// questionNameType returns the lowercased query name (no trailing dot) and the
// record type string (A, AAAA, HTTPS, ...).
func questionNameType(q []byte) (string, string) {
	var p dnsmessage.Parser
	if _, err := p.Start(q); err != nil {
		return "", ""
	}
	qq, err := p.Question()
	if err != nil {
		return "", ""
	}
	return strings.ToLower(strings.TrimSuffix(qq.Name.String(), ".")), dnsTypeName(qq.Type)
}

func dnsTypeName(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypeSOA:
		return "SOA"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	default:
		return "TYPE" + strconv.Itoa(int(t))
	}
}

func questionName(q []byte) string {
	var p dnsmessage.Parser
	if _, err := p.Start(q); err != nil {
		return ""
	}
	qq, err := p.Question()
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(qq.Name.String(), "."))
}

func nxdomain(q []byte) []byte {
	r := servfail(q)
	if r != nil {
		r[3] = 0x83
		// keep question section count so resolvers accept it
		copy(r[4:6], q[4:6])
		r = append(r, q[12:]...)
	}
	return r
}

// sinkZero builds a NOERROR response answering an A query with 0.0.0.0 or an
// AAAA query with ::, so the client connects nowhere. Returns nil for other
// query types (the caller then falls back to NXDOMAIN).
func sinkZero(q []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	qq, err := p.Question()
	if err != nil {
		return nil
	}
	if qq.Type != dnsmessage.TypeA && qq.Type != dnsmessage.TypeAAAA {
		return nil
	}
	rh := dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true}
	b := dnsmessage.NewBuilder(nil, rh)
	if b.StartQuestions() != nil || b.Question(qq) != nil {
		return nil
	}
	if b.StartAnswers() != nil {
		return nil
	}
	ah := dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 10}
	if qq.Type == dnsmessage.TypeA {
		_ = b.AResource(ah, dnsmessage.AResource{A: [4]byte{0, 0, 0, 0}})
	} else {
		_ = b.AAAAResource(ah, dnsmessage.AAAAResource{AAAA: [16]byte{}})
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// record extracts A/AAAA answers and maps them to the question name
// (following CNAME chains back to the original query).
func (f *Forwarder) record(resp []byte) {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) == 0 {
		return
	}
	qname := strings.ToLower(strings.TrimSuffix(qs[0].Name.String(), "."))
	answers, err := p.AllAnswers()
	if err != nil {
		return
	}
	for _, a := range answers {
		ttl := time.Duration(a.Header.TTL) * time.Second
		switch r := a.Body.(type) {
		case *dnsmessage.AResource:
			f.Remember(netip.AddrFrom4(r.A), qname, ttl)
		case *dnsmessage.AAAAResource:
			f.Remember(netip.AddrFrom16(r.AAAA), qname, ttl)
		}
	}
}

// RouterFromRules builds a Router using the rule engine with the "dns"
// pseudo-application.
func RouterFromRules(eval func(rules.Conn) rules.Decision, upstreamIP netip.Addr) Router {
	return func(name string) upstream.Route {
		d := eval(rules.Conn{App: "dns", Host: name, IP: upstreamIP, Port: 53, Proto: "udp", UID: -1})
		return upstream.Route{Action: d.Action, Proxy: d.Proxy, VPN: d.VPN}
	}
}
