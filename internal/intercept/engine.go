// Package intercept is the built-in intercepting HTTP(S) proxy: TLS
// termination with a local CA, request/response recording, hold-and-edit
// interception, and a repeater for re-sending requests.
package intercept

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cyberboba/internal/config"
	"cyberboba/internal/rules"
	"cyberboba/internal/upstream"
)

// Meta identifies the client of a connection.
type Meta struct {
	App    string
	PID    int
	Source string // transparent | proxy | repeater
}

// Event is published to subscribers (type "flow" or "intercept").
type Event struct {
	Type string
	Data interface{}
}

// Engine is the intercepting proxy.
type Engine struct {
	mu      sync.RWMutex
	cfg     config.Intercept
	ca      *CA
	store   *Store
	rw      *rewriter
	dialer  *upstream.Dialer
	publish func(Event)
	logf    func(level, format string, args ...interface{})

	recording atomic.Bool
	holdReq   atomic.Bool
	holdResp  atomic.Bool
	scan      atomic.Bool

	pendMu  sync.Mutex
	pending map[uint64]*held

	listeners []net.Listener
	closed    chan struct{}
	wg        sync.WaitGroup

	// ClientLookup identifies the local process behind a client socket
	// (src = client address, dst = our listener address). Optional.
	ClientLookup func(src, dst netip.AddrPort) (app string, pid int)
}

type decision struct {
	raw  string
	drop bool
}

type held struct {
	flow *Flow
	ch   chan decision
}

// New creates the engine; the CA is loaded or created from cfg.CADir.
func New(cfg config.Intercept, d *upstream.Dialer, publish func(Event), logf func(level, format string, args ...interface{})) (*Engine, error) {
	if logf == nil {
		logf = func(string, string, ...interface{}) {}
	}
	if publish == nil {
		publish = func(Event) {}
	}
	ca, err := LoadOrCreateCA(cfg.CADir)
	if err != nil {
		return nil, fmt.Errorf("intercept CA: %w", err)
	}
	e := &Engine{cfg: cfg, ca: ca, store: NewStore(cfg.MaxFlows), rw: newRewriter(), dialer: d, publish: publish, logf: logf,
		pending: map[uint64]*held{}, closed: make(chan struct{})}
	e.recording.Store(true)
	e.scan.Store(true)
	e.holdReq.Store(cfg.HoldRequests)
	e.holdResp.Store(cfg.HoldResponses)
	return e, nil
}

// SetConfig applies a new configuration (listener changes need a restart).
func (e *Engine) SetConfig(cfg config.Intercept) {
	e.mu.Lock()
	old := e.cfg
	e.cfg = cfg
	e.mu.Unlock()
	e.store.SetMax(cfg.MaxFlows)
	if old.HoldRequests != cfg.HoldRequests {
		e.holdReq.Store(cfg.HoldRequests)
	}
	if old.HoldResponses != cfg.HoldResponses {
		e.holdResp.Store(cfg.HoldResponses)
	}
	e.publish(Event{Type: "intercept", Data: e.Status()})
}

// Config returns the current configuration.
func (e *Engine) Config() config.Intercept {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// CA exposes the certificate authority.
func (e *Engine) CA() *CA { return e.ca }

// Store exposes the flow store.
func (e *Engine) Store() *Store { return e.store }

// Status is the JSON status object.
type Status struct {
	Enabled       bool         `json:"enabled"`
	Listen        string       `json:"listen"`
	Recording     bool         `json:"recording"`
	Scan          bool         `json:"scan"`
	HoldRequests  bool         `json:"hold_requests"`
	HoldResponses bool         `json:"hold_responses"`
	Flows         int          `json:"flows"`
	Pending       int          `json:"pending"`
	CACert        string       `json:"ca_cert"`
	CAFingerprint string       `json:"ca_fingerprint"`
	CAInstalled   bool         `json:"ca_installed"`
	CAExpires     time.Time    `json:"ca_expires"`
	Upstream      config.Route `json:"upstream"`
	Scope         config.Scope `json:"scope"`
	Passthrough   []string     `json:"passthrough"`
	VerifyTLS     bool         `json:"verify_upstream_tls"`
	MaxFlows      int          `json:"max_flows"`
	MaxBody       int          `json:"max_body"`
}

// Status builds the status object.
func (e *Engine) Status() Status {
	cfg := e.Config()
	e.pendMu.Lock()
	pending := len(e.pending)
	e.pendMu.Unlock()
	st := Status{Enabled: cfg.Enabled, Listen: cfg.Listen, Recording: e.recording.Load(), Scan: e.scan.Load(), HoldRequests: e.holdReq.Load(),
		HoldResponses: e.holdResp.Load(), Flows: e.store.Count(), Pending: pending, CACert: e.ca.CertPath(),
		CAFingerprint: e.ca.Fingerprint(), CAInstalled: e.ca.InstalledInSystem(), CAExpires: e.ca.NotAfter(),
		Upstream: cfg.Upstream, Scope: cfg.Scope, Passthrough: cfg.Passthrough, VerifyTLS: cfg.VerifyUpstreamTLS,
		MaxFlows: cfg.MaxFlows, MaxBody: cfg.MaxBody}
	if st.Scope.Include == nil {
		st.Scope.Include = []string{}
	}
	if st.Scope.Exclude == nil {
		st.Scope.Exclude = []string{}
	}
	if st.Passthrough == nil {
		st.Passthrough = []string{}
	}
	if st.Upstream.Action == "" {
		st.Upstream.Action = config.ActionDirect
	}
	return st
}

// Toggle changes runtime switches; nil pointers leave a switch unchanged.
func (e *Engine) Toggle(recording, scan, holdReq, holdResp *bool) Status {
	if recording != nil {
		e.recording.Store(*recording)
	}
	if scan != nil {
		e.scan.Store(*scan)
	}
	if holdReq != nil {
		e.holdReq.Store(*holdReq)
		if !*holdReq {
			e.releaseAll(StatePendingRequest)
		}
	}
	if holdResp != nil {
		e.holdResp.Store(*holdResp)
		if !*holdResp {
			e.releaseAll(StatePendingResponse)
		}
	}
	st := e.Status()
	e.publish(Event{Type: "intercept", Data: st})
	return st
}

// InScope reports whether host matches the scope.
func (e *Engine) InScope(host string) bool {
	cfg := e.Config()
	host = strings.ToLower(host)
	for _, p := range cfg.Scope.Exclude {
		if rules.MatchHost(strings.ToLower(p), host) {
			return false
		}
	}
	if len(cfg.Scope.Include) == 0 {
		return true
	}
	for _, p := range cfg.Scope.Include {
		if rules.MatchHost(strings.ToLower(p), host) {
			return true
		}
	}
	return false
}

func (e *Engine) passthrough(host string) bool {
	cfg := e.Config()
	host = strings.ToLower(host)
	for _, p := range cfg.Passthrough {
		if rules.MatchHost(strings.ToLower(p), host) {
			return true
		}
	}
	return false
}

// --- listeners ---

// Start opens the explicit HTTP proxy listener.
func (e *Engine) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	e.listeners = append(e.listeners, ln)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-e.closed:
					return
				default:
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			go e.handleExplicit(c)
		}
	}()
	return nil
}

// Stop closes listeners.
func (e *Engine) Stop() {
	select {
	case <-e.closed:
		return
	default:
	}
	close(e.closed)
	for _, l := range e.listeners {
		l.Close()
	}
	e.wg.Wait()
}

// handleExplicit serves one client of the explicit proxy listener.
func (e *Engine) handleExplicit(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReaderSize(c, 64*1024)
	req, err := http.ReadRequest(br)
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	meta := Meta{Source: "proxy"}
	if e.ClientLookup != nil {
		if src, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
			if dst, err := netip.ParseAddrPort(c.LocalAddr().String()); err == nil {
				meta.App, meta.PID = e.ClientLookup(src, dst)
			}
		}
	}
	if req.Method == http.MethodConnect {
		host, portStr, err := net.SplitHostPort(req.Host)
		if err != nil {
			host, portStr = req.Host, "443"
		}
		port, _ := strconv.Atoi(portStr)
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			c.Close()
			return
		}
		var ip netip.Addr
		if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			ip, host = a, ""
		}
		e.HandleConn(&bufConn{Conn: c, r: br}, nil, host, ip, port, meta)
		return
	}
	// Plain absolute-URI request(s) on this connection.
	sess := e.newSession(&bufConn{Conn: c, r: br}, "", 0, false, meta)
	defer sess.close()
	for {
		if req.URL == nil || !req.URL.IsAbs() {
			if req.Host == "" {
				io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
				return
			}
			req.URL.Scheme, req.URL.Host = "http", req.Host
		}
		host := req.URL.Hostname()
		port, _ := strconv.Atoi(req.URL.Port())
		useTLS := req.URL.Scheme == "https"
		if port == 0 {
			port = 80
			if useTLS {
				port = 443
			}
		}
		sess.host, sess.port, sess.tls = host, port, useTLS
		if !sess.handle(req) {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Minute))
		req, err = http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})
	}
}

// bufConn lets a bufio.Reader-fronted connection be used as a net.Conn.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// prefixConn replays already-read bytes before the underlying conn.
type prefixConn struct {
	net.Conn
	head []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.head) > 0 {
		n := copy(b, p.head)
		p.head = p.head[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// HandleConn takes over a raw client connection to host:port. head holds
// bytes already read from the client (may be nil). The engine decides
// between TLS termination, plain HTTP and passthrough.
func (e *Engine) HandleConn(c net.Conn, head []byte, host string, ip netip.Addr, port int, meta Meta) {
	if meta.Source == "" {
		meta.Source = "transparent"
	}
	if len(head) > 0 {
		c = &prefixConn{Conn: c, head: head}
	}
	name := host
	if name == "" && ip.IsValid() {
		name = ip.String()
	}
	if e.passthrough(name) {
		e.tunnel(c, name, ip, port)
		return
	}
	// Decide TLS: peek first byte.
	br := bufio.NewReaderSize(c, 64*1024)
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	first, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return
	}
	bc := &bufConn{Conn: c, r: br}
	if first[0] == 0x16 {
		tc := tls.Server(bc, &tls.Config{
			NextProtos: []string{"http/1.1"},
			GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
				sni := h.ServerName
				if sni == "" {
					sni = name
				}
				return e.ca.Leaf(sni)
			},
		})
		_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tc.Handshake(); err != nil {
			e.logf("debug", "intercept: tls handshake with client for %s: %v", name, err)
			tc.Close()
			return
		}
		_ = tc.SetDeadline(time.Time{})
		if sni := tc.ConnectionState().ServerName; sni != "" && host == "" {
			host = sni
		}
		e.serveHTTP(tc, host, ip, port, true, meta)
		return
	}
	e.serveHTTP(bc, host, ip, port, false, meta)
}

// tunnel relays bytes without inspection.
func (e *Engine) tunnel(c net.Conn, host string, ip netip.Addr, port int) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	up, err := e.dialUpstream(ctx, host, ip, port, false)
	cancel()
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func (e *Engine) serveHTTP(c net.Conn, host string, ip netip.Addr, port int, useTLS bool, meta Meta) {
	if host == "" && ip.IsValid() {
		host = ip.String()
	}
	sess := e.newSession(c, host, port, useTLS, meta)
	sess.ip = ip
	defer sess.close()
	br := bufio.NewReaderSize(c, 64*1024)
	for {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Minute))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		if !sess.handle(req) {
			return
		}
	}
}

// --- session: one client connection, possibly many requests ---

type session struct {
	e      *Engine
	client net.Conn
	host   string
	ip     netip.Addr
	port   int
	tls    bool
	meta   Meta
	up     net.Conn
	upbr   *bufio.Reader
	upKey  string
}

func (e *Engine) newSession(c net.Conn, host string, port int, useTLS bool, meta Meta) *session {
	return &session{e: e, client: c, host: host, port: port, tls: useTLS, meta: meta}
}

func (s *session) close() {
	if s.up != nil {
		s.up.Close()
		s.up = nil
	}
	s.client.Close()
}

func (s *session) upstream(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	key := fmt.Sprintf("%s:%d/%v", s.host, s.port, s.tls)
	if s.up != nil && s.upKey == key {
		return s.up, s.upbr, nil
	}
	if s.up != nil {
		s.up.Close()
		s.up = nil
	}
	c, err := s.e.dialUpstream(ctx, s.host, s.ip, s.port, s.tls)
	if err != nil {
		return nil, nil, err
	}
	s.up, s.upbr, s.upKey = c, bufio.NewReaderSize(c, 64*1024), key
	return s.up, s.upbr, nil
}

func (s *session) dropUpstream() {
	if s.up != nil {
		s.up.Close()
		s.up = nil
	}
}

// dialUpstream connects (and TLS-wraps) to the destination through the
// configured upstream route.
func (e *Engine) dialUpstream(ctx context.Context, host string, ip netip.Addr, port int, useTLS bool) (net.Conn, error) {
	cfg := e.Config()
	route := upstream.Route{Action: cfg.Upstream.Action, Proxy: cfg.Upstream.Proxy, VPN: cfg.Upstream.VPN}
	if route.Action == "" {
		route.Action = config.ActionDirect
	}
	target := upstream.Target{Host: host, IP: ip, Port: port}
	if a, err := netip.ParseAddr(host); err == nil {
		target.IP, target.Host = a, ""
	}
	if !target.IP.IsValid() && target.Host != "" && route.Action != config.ActionProxy {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", target.Host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: %v", target.Host, err)
		}
		target.IP = ips[0].Unmap()
		for _, a := range ips {
			if a.Unmap().Is4() {
				target.IP = a.Unmap()
				break
			}
		}
	}
	c, _, err := e.dialer.Dial(ctx, route, target)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return c, nil
	}
	sni := host
	if _, err := netip.ParseAddr(sni); err == nil {
		sni = ""
	}
	tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: !cfg.VerifyUpstreamTLS, NextProtos: []string{"http/1.1"}})
	_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		c.Close()
		return nil, fmt.Errorf("tls to %s: %w", host, err)
	}
	_ = tc.SetDeadline(time.Time{})
	return tc, nil
}

// handle processes one request; returns false when the connection must end.
func (s *session) handle(req *http.Request) bool {
	e := s.e
	cfg := e.Config()
	f := &Flow{Time: time.Now(), Source: s.meta.Source, App: s.meta.App, PID: s.meta.PID, Host: s.host, Port: s.port, TLS: s.tls,
		State: StateSent}
	f.InScope = e.InScope(s.host)
	fillRequest(f, req, s.tls, s.host, s.port)

	// Read the request body (bounded).
	body, truncated, err := readAll(req.Body, cfg.MaxBody, 64<<20)
	req.Body.Close()
	if err != nil {
		s.fail(f, "read request body: "+err.Error())
		return false
	}
	f.priv().reqBody, f.ReqBodyTruncated, f.ReqSize = body, truncated, int64(len(body))
	record := e.recording.Load() && (!cfg.RecordOnlyScope || f.InScope)
	if record {
		e.store.Add(f)
	}

	// Hold the request?
	if record && f.InScope && e.holdReq.Load() {
		f.setState(StatePendingRequest)
		f.Intercepted = true
		e.emit(f)
		d := e.hold(f)
		if d.drop {
			f.setState(StateDropped)
			e.emit(f)
			writeSimple(s.client, 502, "dropped by interceptor")
			return false
		}
		if d.raw != "" {
			nreq, nbody, err := parseRawRequest(d.raw)
			if err != nil {
				s.fail(f, "edited request: "+err.Error())
				writeSimple(s.client, 400, "bad edited request: "+err.Error())
				return false
			}
			req, body = nreq, nbody
			f.Edited = true
			fillRequest(f, req, s.tls, s.host, s.port)
			f.priv().reqBody, f.ReqSize, f.ReqBodyTruncated = body, int64(len(body)), false
		}
		f.setState(StateSent)
	}
	// Apply request match & replace (skipped for repeater via source check).
	if s.meta.Source != "repeater" && len(cfg.Rewrites) > 0 {
		if nb, ch := e.rw.applyRequest(cfg.Rewrites, f, body); ch {
			body = nb
			f.Rewritten = true
			syncReqHeaders(req, f.ReqHeaders)
			if req.URL != nil {
				if u, err := req.URL.Parse(f.Path); err == nil {
					req.URL = u
				}
			}
			req.RequestURI = ""
		}
	}
	if record {
		e.emit(f)
	}

	// Forward.
	resp, respBody, err := s.roundTrip(req, body, f)
	if err != nil {
		s.fail(f, err.Error())
		writeSimple(s.client, 502, "upstream error: "+err.Error())
		return false
	}
	fillResponse(f, resp)

	if resp.StatusCode == http.StatusSwitchingProtocols {
		f.WebSocket = true
		f.DurationMS = time.Since(f.Time).Milliseconds()
		f.setState(StateDone)
		if record {
			e.emit(f)
		}
		resp.Body = http.NoBody
		if err := resp.Write(s.client); err != nil {
			return false
		}
		s.websocket()
		return false
	}

	// Hold the response?
	if record && f.InScope && e.holdResp.Load() {
		f.priv().respBody = respBody
		f.setState(StatePendingResponse)
		f.Intercepted = true
		e.emit(f)
		d := e.hold(f)
		if d.drop {
			f.setState(StateDropped)
			e.emit(f)
			writeSimple(s.client, 502, "dropped by interceptor")
			return false
		}
		if d.raw != "" {
			nresp, nbody, err := parseRawResponse(d.raw, req)
			if err != nil {
				s.fail(f, "edited response: "+err.Error())
				return false
			}
			resp, respBody = nresp, nbody
			f.Edited = true
			fillResponse(f, resp)
		}
	}
	if s.meta.Source != "repeater" && len(cfg.Rewrites) > 0 {
		if nb, ch := e.rw.applyResponse(cfg.Rewrites, f, respBody); ch {
			respBody = nb
			f.Rewritten = true
			syncRespHeaders(resp, f.RespHeaders)
		}
	}
	f.priv().respBody = respBody
	f.RespSize = int64(len(respBody))
	f.DurationMS = time.Since(f.Time).Milliseconds()
	if record && e.scan.Load() {
		f.Findings = scanFlow(f, capBody(body), capBody(respBody))
	}
	f.setState(StateDone)
	if record {
		e.emit(f)
	}

	// Write to client with a concrete body length.
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	resp.ContentLength = int64(len(respBody))
	resp.TransferEncoding = nil
	resp.Header.Del("Transfer-Encoding")
	if resp.StatusCode != 204 && resp.StatusCode != 304 && resp.StatusCode >= 200 && req.Method != http.MethodHead {
		resp.Header.Set("Content-Length", strconv.Itoa(len(respBody)))
	}
	if err := resp.Write(s.client); err != nil {
		return false
	}
	if req.Close || resp.Close || strings.EqualFold(req.Header.Get("Connection"), "close") {
		return false
	}
	return true
}

// roundTrip sends the request upstream and reads the whole response.
func (s *session) roundTrip(req *http.Request, body []byte, f *Flow) (*http.Response, []byte, error) {
	cfg := s.e.Config()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		up, upbr, err := s.upstream(ctx)
		if err != nil {
			return nil, nil, err
		}
		out := cloneForUpstream(req, body, s.host)
		_ = up.SetDeadline(time.Now().Add(2 * time.Minute))
		if err := out.Write(up); err != nil {
			lastErr = err
			s.dropUpstream()
			continue
		}
		resp, err := http.ReadResponse(upbr, out)
		if err != nil {
			lastErr = err
			s.dropUpstream()
			if attempt == 0 && body != nil {
				continue
			}
			break
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, nil, nil
		}
		rb, truncated, err := readAll(resp.Body, cfg.MaxBody, 256<<20)
		resp.Body.Close()
		_ = up.SetDeadline(time.Time{})
		if err != nil {
			s.dropUpstream()
			return nil, nil, fmt.Errorf("read response body: %w", err)
		}
		f.RespBodyTruncated = truncated
		if resp.Close {
			s.dropUpstream()
		}
		return resp, rb, nil
	}
	if lastErr == nil {
		lastErr = errors.New("upstream failed")
	}
	return nil, nil, lastErr
}

// websocket relays frames after a 101 response.
func (s *session) websocket() {
	up := s.up
	if up == nil {
		return
	}
	s.up = nil
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, s.client); done <- struct{}{} }()
	go func() {
		if s.upbr != nil && s.upbr.Buffered() > 0 {
			b, _ := s.upbr.Peek(s.upbr.Buffered())
			s.client.Write(b)
		}
		io.Copy(s.client, up)
		done <- struct{}{}
	}()
	<-done
	up.Close()
}

func (s *session) fail(f *Flow, msg string) {
	f.Error = msg
	f.DurationMS = time.Since(f.Time).Milliseconds()
	f.setState(StateError)
	s.e.emit(f)
	s.e.logf("debug", "intercept: %s %s: %s", f.Method, f.URL, msg)
}

func (e *Engine) emit(f *Flow) {
	if f.ID != 0 {
		e.publish(Event{Type: "flow", Data: f.snapshot()})
	}
}

func (f *Flow) setState(s State) {
	f.priv().mu.Lock()
	f.State = s
	f.priv().mu.Unlock()
}

// --- hold queue ---

func (e *Engine) hold(f *Flow) decision {
	h := &held{flow: f, ch: make(chan decision, 1)}
	e.pendMu.Lock()
	e.pending[f.ID] = h
	e.pendMu.Unlock()
	e.publish(Event{Type: "intercept", Data: e.Status()})
	d := <-h.ch
	e.pendMu.Lock()
	delete(e.pending, f.ID)
	e.pendMu.Unlock()
	e.publish(Event{Type: "intercept", Data: e.Status()})
	return d
}

// Pending lists held flows (oldest first).
func (e *Engine) Pending() []FlowDetail {
	e.pendMu.Lock()
	hs := make([]*held, 0, len(e.pending))
	for _, h := range e.pending {
		hs = append(hs, h)
	}
	e.pendMu.Unlock()
	out := make([]FlowDetail, 0, len(hs))
	for _, h := range hs {
		out = append(out, h.flow.Detail())
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].ID < out[j-1].ID; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Forward releases a held flow, optionally with an edited raw message.
func (e *Engine) Forward(id uint64, raw string) error {
	e.pendMu.Lock()
	h, ok := e.pending[id]
	e.pendMu.Unlock()
	if !ok {
		return fmt.Errorf("flow %d is not pending", id)
	}
	select {
	case h.ch <- decision{raw: raw}:
	default:
	}
	return nil
}

// Drop rejects a held flow.
func (e *Engine) Drop(id uint64) error {
	e.pendMu.Lock()
	h, ok := e.pending[id]
	e.pendMu.Unlock()
	if !ok {
		return fmt.Errorf("flow %d is not pending", id)
	}
	select {
	case h.ch <- decision{drop: true}:
	default:
	}
	return nil
}

// ForwardAll releases everything unchanged.
func (e *Engine) ForwardAll() int {
	e.pendMu.Lock()
	hs := make([]*held, 0, len(e.pending))
	for _, h := range e.pending {
		hs = append(hs, h)
	}
	e.pendMu.Unlock()
	for _, h := range hs {
		select {
		case h.ch <- decision{}:
		default:
		}
	}
	return len(hs)
}

func (e *Engine) releaseAll(state State) {
	e.pendMu.Lock()
	var hs []*held
	for _, h := range e.pending {
		if h.flow.snapshot().State == state {
			hs = append(hs, h)
		}
	}
	e.pendMu.Unlock()
	for _, h := range hs {
		select {
		case h.ch <- decision{}:
		default:
		}
	}
}

// --- repeater ---

// Send executes a raw request against host:port and returns the recorded
// flow. The flow is stored with source "repeater".
func (e *Engine) Send(host string, port int, useTLS bool, raw string, follow bool, timeout time.Duration) (FlowDetail, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	req, body, err := parseRawRequest(raw)
	if err != nil {
		return FlowDetail{}, err
	}
	if host == "" {
		host = req.Host
		if h, p, err := net.SplitHostPort(host); err == nil {
			host = h
			if port == 0 {
				port, _ = strconv.Atoi(p)
			}
		}
	}
	if port == 0 {
		port = 80
		if useTLS {
			port = 443
		}
	}
	var last FlowDetail
	for hop := 0; hop < 10; hop++ {
		f := &Flow{Time: time.Now(), Source: "repeater", Host: host, Port: port, TLS: useTLS, State: StateSent}
		f.InScope = e.InScope(host)
		fillRequest(f, req, useTLS, host, port)
		f.priv().reqBody, f.ReqSize = body, int64(len(body))
		e.store.Add(f)
		e.emit(f)
		s := e.newSession(nopConn{}, host, port, useTLS, Meta{Source: "repeater"})
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_, _, err := s.upstream(ctx)
		cancel()
		if err != nil {
			s.fail(f, err.Error())
			s.close()
			return f.Detail(), err
		}
		resp, respBody, err := s.roundTrip(req, body, f)
		s.close()
		if err != nil {
			s.fail(f, err.Error())
			return f.Detail(), err
		}
		fillResponse(f, resp)
		f.priv().respBody = respBody
		f.RespSize = int64(len(respBody))
		f.DurationMS = time.Since(f.Time).Milliseconds()
		f.setState(StateDone)
		e.emit(f)
		last = f.Detail()
		loc := resp.Header.Get("Location")
		if !follow || loc == "" || resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}
		u, err := url.Parse(loc)
		if err != nil {
			break
		}
		if u.IsAbs() {
			host = u.Hostname()
			useTLS = u.Scheme == "https"
			port, _ = strconv.Atoi(u.Port())
			if port == 0 {
				port = 80
				if useTLS {
					port = 443
				}
			}
		}
		req, _ = http.NewRequest(http.MethodGet, u.String(), nil)
		if !u.IsAbs() {
			req.URL.Scheme = schemeOf(useTLS)
			req.URL.Host = net.JoinHostPort(host, strconv.Itoa(port))
		}
		req.Host = host
		body = nil
	}
	return last, nil
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error                     { return nil }
func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(b []byte) (int, error)      { return len(b), nil }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

// --- helpers ---

func schemeOf(useTLS bool) string {
	if useTLS {
		return "https"
	}
	return "http"
}

func fillRequest(f *Flow, req *http.Request, useTLS bool, host string, port int) {
	f.Method = req.Method
	f.Proto = req.Proto
	if f.Proto == "" {
		f.Proto = "HTTP/1.1"
	}
	path := req.URL.RequestURI()
	if req.RequestURI != "" && !req.URL.IsAbs() {
		path = req.RequestURI
	}
	if path == "" {
		path = "/"
	}
	f.Path = path
	hostport := host
	if (useTLS && port != 443) || (!useTLS && port != 80) {
		hostport = net.JoinHostPort(host, strconv.Itoa(port))
	}
	f.URL = schemeOf(useTLS) + "://" + hostport + path
	f.ReqHeaders = orderedHeaders(req.Header, req.Host)
}

// syncReqHeaders rewrites req.Header from the ordered flow header list.
func syncReqHeaders(req *http.Request, hs []Header) {
	req.Header = http.Header{}
	for _, h := range hs {
		if strings.EqualFold(h[0], "Host") {
			req.Host = h[1]
			continue
		}
		req.Header.Add(h[0], h[1])
	}
}

// syncRespHeaders rewrites resp.Header from the ordered flow header list.
func syncRespHeaders(resp *http.Response, hs []Header) {
	resp.Header = http.Header{}
	for _, h := range hs {
		resp.Header.Add(h[0], h[1])
	}
}

func fillResponse(f *Flow, resp *http.Response) {
	f.Status = resp.StatusCode
	f.StatusText = resp.Status
	if f.StatusText == "" {
		f.StatusText = strconv.Itoa(resp.StatusCode) + " " + http.StatusText(resp.StatusCode)
	}
	f.RespHeaders = orderedHeaders(resp.Header, "")
	ct := resp.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i > 0 {
		ct = ct[:i]
	}
	f.ContentType = strings.TrimSpace(ct)
}

// orderedHeaders flattens a header map deterministically (Host first).
func orderedHeaders(h http.Header, host string) []Header {
	var out []Header
	if host != "" {
		out = append(out, Header{"Host", host})
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	// stable: keep canonical insertion-ish order by sorting
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, Header{k, v})
		}
	}
	if out == nil {
		out = []Header{}
	}
	return out
}

// readAll reads up to hard bytes, keeping the first keep bytes.
func readAll(r io.Reader, keep, hard int) ([]byte, bool, error) {
	if r == nil {
		return nil, false, nil
	}
	var buf bytes.Buffer
	n, err := io.CopyN(&buf, r, int64(hard)+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	if n > int64(hard) {
		return nil, false, fmt.Errorf("body exceeds %d bytes", hard)
	}
	b := buf.Bytes()
	if len(b) > keep {
		return b[:keep], true, nil
	}
	return b, false, nil
}

// cloneForUpstream prepares a request read from a client for writing to a
// server connection.
func cloneForUpstream(req *http.Request, body []byte, host string) *http.Request {
	out := req.Clone(context.Background())
	out.RequestURI = ""
	if out.URL == nil {
		out.URL = &url.URL{}
	}
	// Write() emits origin-form when URL has no scheme/host.
	out.URL.Scheme, out.URL.Host = "", ""
	if out.URL.Path == "" && out.URL.RawPath == "" && req.RequestURI != "" {
		if u, err := url.ParseRequestURI(req.RequestURI); err == nil {
			out.URL = u
			out.URL.Scheme, out.URL.Host = "", ""
		}
	}
	if out.Host == "" {
		out.Host = host
	}
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	out.TransferEncoding = nil
	out.Header.Del("Transfer-Encoding")
	if len(body) > 0 || req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch {
		out.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Proxy-Authorization")
	if strings.Contains(strings.ToLower(out.Header.Get("Accept-Encoding")), "br") {
		// keep as-is; bodies are stored compressed if the server compresses
	}
	return out
}

// parseRawRequest parses an HTTP/1.x request text (as edited by a human or
// an agent). Tolerates \n line endings and recomputes Content-Length.
func parseRawRequest(raw string) (*http.Request, []byte, error) {
	raw = normalizeCRLF(raw)
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return nil, nil, err
	}
	body, _ := io.ReadAll(req.Body)
	req.Body.Close()
	// If no Content-Length/Transfer-Encoding was present, ReadRequest
	// yields an empty body; recover trailing bytes after the blank line.
	if len(body) == 0 && req.ContentLength <= 0 && len(req.TransferEncoding) == 0 {
		if i := strings.Index(raw, "\r\n\r\n"); i >= 0 && i+4 < len(raw) {
			body = []byte(raw[i+4:])
		}
	}
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil
	req.Header.Del("Transfer-Encoding")
	req.Body = io.NopCloser(bytes.NewReader(body))
	return req, body, nil
}

func parseRawResponse(raw string, req *http.Request) (*http.Response, []byte, error) {
	raw = normalizeCRLF(raw)
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), req)
	if err != nil {
		return nil, nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(body) == 0 && resp.ContentLength <= 0 && len(resp.TransferEncoding) == 0 {
		if i := strings.Index(raw, "\r\n\r\n"); i >= 0 && i+4 < len(raw) {
			body = []byte(raw[i+4:])
		}
	}
	resp.TransferEncoding = nil
	resp.Header.Del("Transfer-Encoding")
	return resp, body, nil
}

func normalizeCRLF(raw string) string {
	// Normalize the head (up to the first blank line) to CRLF, keep the body as-is.
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	i := strings.Index(raw, "\n\n")
	if i < 0 {
		return strings.ReplaceAll(raw, "\n", "\r\n") + "\r\n\r\n"
	}
	head := strings.ReplaceAll(raw[:i], "\n", "\r\n")
	return head + "\r\n\r\n" + raw[i+2:]
}

func writeSimple(c net.Conn, code int, msg string) {
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
}
