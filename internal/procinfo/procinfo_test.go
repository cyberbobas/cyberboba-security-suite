package procinfo

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestParseHexAddr(t *testing.T) {
	ap, err := parseHexAddr("0100007F:1F90")
	if err != nil || ap.String() != "127.0.0.1:8080" {
		t.Fatalf("got %v %v", ap, err)
	}
	ap, err = parseHexAddr("00000000000000000000000001000000:0035")
	if err != nil || ap.Addr().String() != "::1" || ap.Port() != 53 {
		t.Fatalf("got %v %v", ap, err)
	}
}

func TestLookupSelf(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, _ := ln.Accept()
	defer s.Close()
	src := netip.MustParseAddrPort(c.LocalAddr().String())
	dst := netip.MustParseAddrPort(c.RemoteAddr().String())
	r := New()
	p, uid, err := r.Lookup(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if p.PID != os.Getpid() || uid != os.Getuid() {
		t.Fatalf("got pid %d uid %d want %d %d", p.PID, uid, os.Getpid(), os.Getuid())
	}
	if p.Name == "" || p.Exe == "" {
		t.Fatalf("empty identity %+v", p)
	}
	if r.ListeningPID(netip.MustParseAddrPort(ln.Addr().String())) != os.Getpid() {
		t.Fatal("ListeningPID")
	}
}
