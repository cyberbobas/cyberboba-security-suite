package upstream

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"cyberboba/internal/config"
)

// tiny SOCKS5 server for tests (no auth, CONNECT only)
func socksServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 512)
				n, _ := io.ReadAtLeast(c, buf, 2)
				if n < 2 || buf[0] != 5 {
					return
				}
				if n < 2+int(buf[1]) {
					io.ReadFull(c, buf[n:2+int(buf[1])])
				}
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, buf[:4]); err != nil {
					return
				}
				var host string
				switch buf[3] {
				case 1:
					io.ReadFull(c, buf[:4])
					host = net.IP(buf[:4]).String()
				case 3:
					io.ReadFull(c, buf[:1])
					l := int(buf[0])
					io.ReadFull(c, buf[:l])
					host = string(buf[:l])
				}
				io.ReadFull(c, buf[:2])
				port := int(buf[0])<<8 | int(buf[1])
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func httpProxyServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				line := string(buf[:n])
				var target string
				if _, err := fmtSscanf(line, &target); err != nil {
					return
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func fmtSscanf(line string, target *string) (int, error) {
	var method, proto string
	n, err := sscan(line, &method, target, &proto)
	return n, err
}

func sscan(line string, a ...*string) (int, error) {
	i := 0
	start := 0
	for idx := 0; idx < len(line) && i < len(a); idx++ {
		ch := line[idx]
		if ch == ' ' || ch == '\r' || ch == '\n' {
			if idx > start {
				*a[i] = line[start:idx]
				i++
			}
			start = idx + 1
		}
	}
	return i, nil
}

func echoServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func TestChain(t *testing.T) {
	echo := echoServer(t)
	s := socksServer(t)
	h := httpProxyServer(t)
	cfg := config.Default()
	cfg.Proxies = []config.Proxy{
		{Name: "s", Type: config.ProxySOCKS5, Addr: s},
		{Name: "h", Type: config.ProxyHTTP, Addr: h, RemoteDNS: true},
		{Name: "c", Type: config.ProxyChain, Hops: []string{"s", "h"}},
	}
	d := New(cfg, nil, nil)
	ap := netip.MustParseAddrPort(echo)
	for _, name := range []string{"s", "h", "c"} {
		conn, via, err := d.Dial(context.Background(), Route{Action: config.ActionProxy, Proxy: name},
			Target{Host: "localhost", IP: ap.Addr(), Port: int(ap.Port())})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if via != name {
			t.Fatalf("via=%s", via)
		}
		conn.Write([]byte("ping"))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("%s: echo failed %v %q", name, err, buf)
		}
		conn.Close()
	}
	// direct
	conn, _, err := d.Dial(context.Background(), Route{Action: config.ActionDirect}, Target{IP: ap.Addr(), Port: int(ap.Port())})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	// block
	if _, _, err := d.Dial(context.Background(), Route{Action: config.ActionBlock}, Target{IP: ap.Addr(), Port: 1}); err == nil {
		t.Fatal("block should fail")
	}
}
