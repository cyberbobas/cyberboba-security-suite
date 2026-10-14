package rules

import (
	"net/netip"
	"testing"

	"cyberboba/internal/config"
)

func TestEngine(t *testing.T) {
	f := false
	rs := []config.Rule{
		{Name: "disabled", Enabled: &f, Action: config.ActionBlock},
		{Name: "lan", Targets: []string{"lan"}, Action: config.ActionDirect},
		{Name: "ff-caido", Apps: []string{"firefox", "*chrome*"}, Ports: []string{"80", "443"}, Action: config.ActionProxy, Proxy: "caido"},
		{Name: "tg-vpn", Apps: []string{"tag:work", "/usr/bin/telegram-desktop"}, Action: config.ActionVPN, VPN: "office"},
		{Name: "host", Targets: []string{"*.example.com", "1.2.3.0/24"}, Action: config.ActionBlock},
		{Name: "user", Users: []string{"1001"}, Action: config.ActionBlock},
		{Name: "default", Action: config.ActionDirect},
	}
	e := Compile(rs)
	cases := []struct {
		c    Conn
		want string
	}{
		{Conn{App: "firefox", IP: netip.MustParseAddr("192.168.1.1"), Port: 443}, "lan"},
		{Conn{App: "firefox", IP: netip.MustParseAddr("8.8.8.8"), Port: 443}, "ff-caido"},
		{Conn{App: "firefox", IP: netip.MustParseAddr("8.8.8.8"), Port: 22}, "default"},
		{Conn{App: "google-chrome", Exe: "/opt/google/chrome/chrome", IP: netip.MustParseAddr("8.8.8.8"), Port: 80}, "ff-caido"},
		{Conn{App: "python3", Tag: "work", IP: netip.MustParseAddr("8.8.8.8"), Port: 5000}, "tg-vpn"},
		{Conn{App: "telegram-desktop", Exe: "/usr/bin/telegram-desktop", IP: netip.MustParseAddr("8.8.8.8"), Port: 5000}, "tg-vpn"},
		{Conn{App: "curl", Host: "api.example.com", IP: netip.MustParseAddr("8.8.8.8"), Port: 443}, "host"},
		{Conn{App: "curl", Host: "example.com", IP: netip.MustParseAddr("8.8.8.8"), Port: 443}, "host"},
		{Conn{App: "curl", Host: "notexample.com", IP: netip.MustParseAddr("8.8.8.8"), Port: 443}, "default"},
		{Conn{App: "curl", IP: netip.MustParseAddr("1.2.3.77"), Port: 443}, "host"},
		{Conn{App: "curl", UID: 1001, IP: netip.MustParseAddr("9.9.9.9"), Port: 443}, "user"},
		{Conn{App: "curl", IP: netip.MustParseAddr("::1"), Port: 443}, "lan"},
	}
	for _, tc := range cases {
		d := e.Evaluate(tc.c)
		if !d.Matched || d.Rule.Name != tc.want {
			t.Errorf("%+v: got %v want %s", tc.c, d, tc.want)
		}
	}
}

func TestMatchHost(t *testing.T) {
	if !MatchHost("*.a.com", "x.y.a.com") || !MatchHost("*.a.com", "a.com") || MatchHost("*.a.com", "ba.com") {
		t.Fatal("wildcard")
	}
	if !MatchHost("*tracker*", "ads.tracker.net") {
		t.Fatal("glob")
	}
}
