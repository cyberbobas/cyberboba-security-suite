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

func TestPickSocketRedirected(t *testing.T) {
	src := netip.MustParseAddrPort("127.0.0.1:54321")
	orig := netip.MustParseAddrPort("8.8.8.8:443")
	proxy := netip.MustParseAddrPort("127.0.0.1:7470")
	nic := netip.MustParseAddrPort("192.168.1.10:54321")
	entries := []sockEntry{{
		local: nic, remote: proxy, uid: 1000, inode: 99, state: tcpEstablished,
	}}
	got := pickSocket(entries, src, orig, []netip.AddrPort{proxy})
	if got == nil || got.inode != 99 {
		t.Fatalf("redirected socket not matched: %+v", got)
	}
	// Exact original dest still wins over a listen leftover.
	entries = append(entries, sockEntry{
		local: src, remote: orig, uid: 1000, inode: 100, state: tcpEstablished,
	})
	got = pickSocket(entries, src, orig, []netip.AddrPort{proxy})
	if got == nil || got.inode != 100 {
		t.Fatalf("exact match should win, got %+v", got)
	}
	if pickSocket(entries, netip.MustParseAddrPort("127.0.0.1:1"), orig, nil) != nil {
		t.Fatal("wrong port must not match")
	}
}

func TestDisplayName(t *testing.T) {
	if (&Process{Name: "chrome", Exe: "/opt/google/chrome/chrome"}).DisplayName() != "chrome" {
		t.Fatal("name")
	}
	if (&Process{Exe: "/usr/bin/curl"}).DisplayName() != "curl" {
		t.Fatal("exe")
	}
	if (&Process{PID: 42}).DisplayName() != "pid-42" {
		t.Fatal("pid")
	}
}

func TestDiagLookupSelf(t *testing.T) {
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
	inode, uid, err := diagLookup(src, dst)
	if err != nil {
		t.Skipf("sock_diag not usable here: %v", err)
	}
	if inode == 0 || uid != os.Getuid() {
		t.Fatalf("inode=%d uid=%d (want uid %d)", inode, uid, os.Getuid())
	}
	if pid := New().pidForInode(inode); pid != os.Getpid() {
		t.Fatalf("inode %d -> pid %d, want %d", inode, pid, os.Getpid())
	}
}
