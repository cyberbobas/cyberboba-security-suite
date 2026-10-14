package netfilter

import (
	"strings"
	"testing"
)

func TestDryRun(t *testing.T) {
	m := New(Options{MarkBase: 0x7400, TCPPort: 7470, DNSPort: 7453, BlockQUIC: true, IPv6: true, DryRun: true})
	if err := m.Install(); err != nil {
		t.Fatal(err)
	}
	cmds := strings.Join(m.Commands(), "\n")
	for _, want := range []string{
		"iptables -t nat -A CYBERBOBA_OUT -m mark --mark 0x7400/0xffffff00 -j RETURN",
		"iptables -t nat -A CYBERBOBA_OUT -p tcp --syn -j REDIRECT --to-ports 7470",
		"iptables -t nat -A CYBERBOBA_OUT -p udp --dport 53 -j REDIRECT --to-ports 7453",
		"iptables -t nat -I OUTPUT 1 -j CYBERBOBA_OUT",
		"iptables -t filter -A CYBERBOBA_FILTER -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable",
		"ip6tables -t nat -A CYBERBOBA_OUT -d ::1/128 -j RETURN",
		"iptables -t raw -A CYBERBOBA_RAW -i lo -j ACCEPT",
		"iptables -t raw -I PREROUTING 1 -j CYBERBOBA_RAW",
	} {
		if !strings.Contains(cmds, want) {
			t.Errorf("missing %q in:\n%s", want, cmds)
		}
	}
	if err := m.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(m.Commands(), "\n"), "iptables -t nat -X CYBERBOBA_OUT") {
		t.Error("uninstall missing")
	}
}
