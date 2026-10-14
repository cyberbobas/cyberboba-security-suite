package firewall

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"cyberboba/internal/config"
)

func newEng(fw config.Firewall) (*Engine, *sync.Mutex, *config.Firewall) {
	var mu sync.Mutex
	stored := fw
	var e *Engine
	e = New(fw, func(string, interface{}) {}, func(fn func(*config.Firewall)) {
		mu.Lock()
		fn(&stored)
		cfg := stored
		mu.Unlock()
		e.SetConfig(cfg)
	}, func() bool { return true }, nil)
	return e, &mu, &stored
}

func conn(app, ip string, port int) Conn {
	a, _ := netip.ParseAddr(ip)
	return Conn{App: app, IP: a, Port: port, Host: app + ".example.com"}
}

func TestOffAllowsAll(t *testing.T) {
	e, _, _ := newEng(config.Firewall{Enabled: true, Mode: "off"})
	if !e.Check(conn("x", "8.8.8.8", 443)).Allow {
		t.Fatal("off should allow")
	}
}

func TestBlockMode(t *testing.T) {
	e, _, _ := newEng(config.Firewall{Enabled: true, Mode: "block"})
	if e.Check(conn("x", "8.8.8.8", 443)).Allow {
		t.Fatal("block mode should deny unknown")
	}
	// loopback always allowed
	if !e.Check(conn("x", "127.0.0.1", 80)).Allow {
		t.Fatal("loopback must be allowed")
	}
}

func TestProgramPermsAndZone(t *testing.T) {
	e, _, _ := newEng(config.Firewall{Enabled: true, Mode: "block", TrustedNets: []string{"lan"}, Programs: []config.FwProgram{
		{App: "firefox", Internet: "allow", Trusted: "block"},
	}})
	if !e.Check(conn("firefox", "8.8.8.8", 443)).Allow {
		t.Fatal("firefox internet should be allowed")
	}
	d := e.Check(conn("firefox", "192.168.1.5", 445))
	if d.Allow || d.Zone != "trusted" {
		t.Fatalf("firefox trusted should be blocked, got %+v", d)
	}
}

func TestInternetLock(t *testing.T) {
	e, _, _ := newEng(config.Firewall{Enabled: true, Mode: "off", InternetLock: true, Programs: []config.FwProgram{
		{App: "updater", LockPass: true, Internet: "allow"},
	}})
	if e.Check(conn("random", "8.8.8.8", 443)).Allow {
		t.Fatal("lock must block non-pass apps")
	}
	if !e.Check(conn("updater", "8.8.8.8", 443)).Allow {
		t.Fatal("lock_pass app must pass")
	}
}

func TestAskAnswerAndRemember(t *testing.T) {
	e, mu, stored := newEng(config.Firewall{Enabled: true, Mode: "ask", AskTimeoutSec: 5, AskTimeoutAction: "block"})
	done := make(chan Decision, 1)
	go func() { done <- e.Check(conn("telegram", "1.2.3.4", 443)) }()
	// wait for the pending ask to appear
	var id uint64
	for i := 0; i < 100; i++ {
		if p := e.Pending(); len(p) == 1 {
			id = p[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if id == 0 {
		t.Fatal("no pending ask appeared")
	}
	if !e.Answer(id, true, true) {
		t.Fatal("answer failed")
	}
	d := <-done
	if !d.Allow {
		t.Fatal("should be allowed after answer")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(stored.Programs) != 1 || stored.Programs[0].App != "telegram" || stored.Programs[0].Internet != "allow" {
		t.Fatalf("remember failed: %+v", stored.Programs)
	}
}

func TestAskTimeout(t *testing.T) {
	e, _, _ := newEng(config.Firewall{Enabled: true, Mode: "ask", AskTimeoutSec: 1, AskTimeoutAction: "block"})
	start := time.Now()
	d := e.Check(conn("slow", "1.2.3.4", 443))
	if d.Allow {
		t.Fatal("timeout should block")
	}
	if time.Since(start) < 900*time.Millisecond {
		t.Fatal("should have waited for timeout")
	}
}

func TestLateAnswerRemembers(t *testing.T) {
	e, mu, stored := newEng(config.Firewall{Enabled: true, Mode: "ask", AskTimeoutSec: 1, AskTimeoutAction: "block"})
	d := e.Check(conn("claude", "1.2.3.4", 443))
	if d.Allow {
		t.Fatal("timeout should block")
	}
	if len(e.Pending()) != 0 {
		t.Fatal("pending should be empty after timeout")
	}
	if !e.Answer(1, true, true) {
		t.Fatal("late Allow must still succeed so the user can remember the app")
	}
	mu.Lock()
	if len(stored.Programs) != 1 || stored.Programs[0].App != "claude" || stored.Programs[0].Internet != "allow" {
		t.Fatalf("late remember failed: %+v", stored.Programs)
	}
	mu.Unlock()
	if !e.Check(conn("claude", "1.2.3.4", 443)).Allow {
		t.Fatal("next claude connection should be allowed after late remember")
	}
}

func TestEmptyAppUsesExe(t *testing.T) {
	e, mu, stored := newEng(config.Firewall{Enabled: true, Mode: "ask", AskTimeoutSec: 5, AskTimeoutAction: "block"})
	c := Conn{Exe: "/home/user/.local/bin/claude", IP: netip.MustParseAddr("1.2.3.4"), Port: 443, Host: "api.anthropic.com"}
	done := make(chan Decision, 1)
	go func() { done <- e.Check(c) }()
	var id uint64
	var app string
	for i := 0; i < 100; i++ {
		if p := e.Pending(); len(p) == 1 {
			id, app = p[0].ID, p[0].App
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if id == 0 {
		t.Fatal("no pending ask")
	}
	if app != "claude" {
		t.Fatalf("expected exe basename, got %q", app)
	}
	if !e.Answer(id, true, true) {
		t.Fatal("answer failed")
	}
	if d := <-done; !d.Allow {
		t.Fatal("should allow")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(stored.Programs) != 1 || stored.Programs[0].App != "claude" {
		t.Fatalf("remembered %+v", stored.Programs)
	}
}

func TestAskCoalescesPerProgram(t *testing.T) {
	e, _, _ := newEng(config.Firewall{Enabled: true, Mode: "ask", AskTimeoutSec: 5, AskTimeoutAction: "block"})
	const n = 6
	results := make(chan Decision, n)
	for i := 0; i < n; i++ {
		go func() { results <- e.Check(conn("chrome", "1.2.3.4", 443)) }()
	}
	// exactly ONE prompt should appear for the program
	var id uint64
	for i := 0; i < 200; i++ {
		p := e.Pending()
		if len(p) == 1 && p[0].Waiting >= 1 {
			id = p[0].ID
			if p[0].Waiting == n {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if id == 0 {
		t.Fatal("expected exactly one coalesced prompt")
	}
	if len(e.Pending()) != 1 {
		t.Fatalf("expected 1 prompt, got %d", len(e.Pending()))
	}
	// one answer releases all coalesced connections
	if !e.Answer(id, true, false) {
		t.Fatal("answer failed")
	}
	for i := 0; i < n; i++ {
		if d := <-results; !d.Allow {
			t.Fatal("all coalesced connections should be allowed by one answer")
		}
	}
	if len(e.Pending()) != 0 {
		t.Fatal("no prompts should remain")
	}
}

func TestNoUIFailsOpen(t *testing.T) {
	var mu sync.Mutex
	stored := config.Firewall{Enabled: true, Mode: "ask", AskTimeoutSec: 30, AskTimeoutAction: "block"}
	// hasUI=false → connections must NOT be held; allowed immediately
	e := New(stored, func(string, interface{}) {}, func(fn func(*config.Firewall)) { mu.Lock(); fn(&stored); mu.Unlock() }, func() bool { return false }, nil)
	start := time.Now()
	d := e.Check(conn("someapp", "1.2.3.4", 443))
	if !d.Allow {
		t.Fatal("with no UI, unknown app must fail OPEN (allow), not block")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("with no UI, must not hold the connection")
	}
	if len(e.Pending()) != 0 {
		t.Fatal("with no UI, no prompt should be created")
	}
}

func TestBlockedHostsApplyEvenWhenOff(t *testing.T) {
	// firewall program-control OFF, but a blocklist present → engine must be
	// Active and must deny matching hosts (and only those).
	e, _, _ := newEng(config.Firewall{Enabled: false, Mode: "off", BlockedHosts: []string{"*.doubleclick.net", "10.0.0.0/8"}})
	if !e.Active() {
		t.Fatal("engine with a blocklist must be Active even when disabled")
	}
	if d := e.Check(conn("chrome", "8.8.8.8", 443)); !d.Allow {
		t.Fatalf("unrelated host must be allowed, got %+v", d)
	}
	// host pattern match (conn() sets Host = app+".example.com"; use a matching app)
	bad := conn("ads.doubleclick.net", "1.2.3.4", 443)
	bad.Host = "ads.doubleclick.net"
	if d := e.Check(bad); d.Allow {
		t.Fatal("blocked domain must be denied")
	}
	// CIDR match on IP
	if d := e.Check(conn("x", "10.1.2.3", 443)); d.Allow {
		t.Fatal("blocked CIDR must be denied")
	}
	// loopback is never blocked
	lb := conn("x", "127.0.0.1", 80)
	lb.Host = "ads.doubleclick.net"
	if d := e.Check(lb); !d.Allow {
		t.Fatal("loopback must never be blocked by the host blocklist")
	}
}

func TestBlockedHostsWithProgramControl(t *testing.T) {
	// blocklist takes precedence over an allow program entry.
	e, _, _ := newEng(config.Firewall{Enabled: true, Mode: "off", BlockedHosts: []string{"evil.test"},
		Programs: []config.FwProgram{{App: "curl", Internet: "allow"}}})
	c := conn("curl", "9.9.9.9", 443)
	c.Host = "evil.test"
	if d := e.Check(c); d.Allow {
		t.Fatalf("blocklist must override an allow entry, got %+v", d)
	}
}
