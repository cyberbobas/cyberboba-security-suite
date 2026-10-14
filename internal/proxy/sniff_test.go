package proxy

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestSniffHTTP(t *testing.T) {
	if h := sniffHost([]byte("GET / HTTP/1.1\r\nUser-Agent: x\r\nHost: Example.com:8080\r\n\r\n")); h != "example.com" {
		t.Fatalf("got %q", h)
	}
	if h := sniffHost([]byte("\x00\x01garbage")); h != "" {
		t.Fatalf("got %q", h)
	}
}

func TestSniffSNI(t *testing.T) {
	c, s := net.Pipe()
	go func() {
		tc := tls.Client(c, &tls.Config{ServerName: "sni.example.org", InsecureSkipVerify: true})
		tc.SetDeadline(time.Now().Add(2 * time.Second))
		_ = tc.Handshake()
		c.Close()
	}()
	buf := make([]byte, 4096)
	s.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := s.Read(buf)
	s.Close()
	if h := sniffHost(buf[:n]); h != "sni.example.org" {
		t.Fatalf("got %q (n=%d)", h, n)
	}
}
