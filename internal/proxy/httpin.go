package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// StartHTTP opens an inbound HTTP proxy listener (CONNECT for any TCP
// target, plus plain absolute-URI HTTP requests). Like the SOCKS5 inbound it
// gives rule-based routing to applications with proxy settings.
func (e *Engine) StartHTTP(addr string) error {
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
			go e.handleHTTP(c)
		}
	}()
	return nil
}

func (e *Engine) handleHTTP(client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReaderSize(client, 64*1024)
	req, err := http.ReadRequest(br)
	if err != nil {
		client.Close()
		return
	}
	var host string
	var port int
	var head []byte
	if req.Method == http.MethodConnect {
		h, p, err := net.SplitHostPort(req.Host)
		if err != nil {
			h, p = req.Host, "443"
		}
		host = h
		port, _ = strconv.Atoi(p)
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			client.Close()
			return
		}
	} else {
		// Absolute-URI request: rewrite to origin-form and forward.
		u := req.URL
		if !u.IsAbs() {
			if req.Host == "" {
				io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
				client.Close()
				return
			}
			u = &url.URL{Scheme: "http", Host: req.Host, Path: req.URL.Path, RawQuery: req.URL.RawQuery}
		}
		host = u.Hostname()
		port, _ = strconv.Atoi(u.Port())
		if port == 0 {
			port = 80
			if u.Scheme == "https" {
				port = 443
			}
		}
		var buf bytes.Buffer
		path := u.RequestURI()
		if path == "" {
			path = "/"
		}
		fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", req.Method, path)
		req.Header.Del("Proxy-Connection")
		req.Header.Del("Proxy-Authorization")
		if req.Header.Get("Host") == "" {
			fmt.Fprintf(&buf, "Host: %s\r\n", u.Host)
		}
		if req.ContentLength > 0 {
			req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
		}
		req.Header.Set("Connection", "close")
		for k, vs := range req.Header {
			for _, v := range vs {
				fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
			}
		}
		buf.WriteString("\r\n")
		if req.Body != nil {
			io.Copy(&buf, io.LimitReader(req.Body, 32<<20))
		}
		head = buf.Bytes()
	}
	_ = client.SetDeadline(time.Time{})
	host = strings.ToLower(strings.Trim(host, "[]"))
	var ip netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		ip, host = a.Unmap(), ""
	}
	src := netip.MustParseAddrPort(client.RemoteAddr().String())
	local := netip.MustParseAddrPort(client.LocalAddr().String())
	// Data the client already pushed after CONNECT (TLS ClientHello) sits in
	// the bufio reader; hand it over as the sniffable head.
	if req.Method == http.MethodConnect {
		_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if n := br.Buffered(); n > 0 {
			head, _ = br.Peek(n)
			head = append([]byte(nil), head...)
			br.Discard(n)
		} else if peek, err := br.Peek(1); err == nil && len(peek) == 1 {
			n := br.Buffered()
			head, _ = br.Peek(n)
			head = append([]byte(nil), head...)
			br.Discard(n)
		}
		_ = client.SetReadDeadline(time.Time{})
	}
	e.serveWithHead(&bufConn{Conn: client, r: br}, src, local, netip.AddrPortFrom(ip, uint16(port)), host, head)
}

// bufConn makes a bufio.Reader-backed connection look like a net.Conn.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
