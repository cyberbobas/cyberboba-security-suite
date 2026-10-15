package vpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberboba/internal/config"
)

func TestRenderSelectiveConfig(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "office.conf")
	os.WriteFile(src, []byte("[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\nTable = 1234\n\n[Peer]\nPublicKey = y\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n"), 0o600)
	cfg := config.Default()
	cfg.VPNs = []config.VPN{{Name: "office", Type: config.VPNWireGuard, Config: src, Mode: config.VPNModeSelective}}
	m := New(cfg, dir, nil, nil)
	tn, _ := m.get("office")
	w := tn.be.(*wireguard)
	path, iface, err := w.renderConfig()
	if err != nil {
		t.Fatal(err)
	}
	if iface != "office" {
		t.Fatalf("iface %q", iface)
	}
	out, _ := os.ReadFile(path)
	s := string(out)
	if !strings.Contains(s, "Table = off") || strings.Contains(s, "Table = 1234") || !strings.Contains(s, "# DNS = 10.0.0.1") {
		t.Fatalf("bad render:\n%s", s)
	}
	if strings.Count(s, "Table = off") != 1 {
		t.Fatalf("Table set twice:\n%s", s)
	}
	if !strings.Contains(s, "PersistentKeepalive = 25") {
		t.Fatalf("keepalive not injected:\n%s", s)
	}
	mark, table := m.markTable("office")
	if mark != 0x7401 || table != 7401 {
		t.Fatalf("mark/table %x %d", mark, table)
	}
	if _, ok, err := m.MarkFor("office"); err == nil || ok {
		t.Fatal("MarkFor should fail while down")
	}
}

func TestInterfaceName(t *testing.T) {
	if n := InterfaceName(config.VPN{Name: "a very long profile name", Type: config.VPNOpenVPN}); len(n) > 15 {
		t.Fatal(n)
	}
	if n := InterfaceName(config.VPN{Type: config.VPNWireGuard, Config: "/x/wg0.conf"}); n != "wg0" {
		t.Fatal(n)
	}
}

func TestInferMode(t *testing.T) {
	if InferMode("[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\n") != config.VPNModeFull {
		t.Fatal("full")
	}
	if InferMode("[Peer]\nAllowedIPs = 10.0.0.0/8\n") != config.VPNModeSelective {
		t.Fatal("selective")
	}
	if InferMode("redirect-gateway def1") != config.VPNModeFull {
		t.Fatal("openvpn")
	}
}

func TestEnsureKeepalive(t *testing.T) {
	in := []string{"[Peer]", "PublicKey = x", "PersistentKeepalive = 0", ""}
	out := strings.Join(ensureKeepalive(in), "\n")
	if !strings.Contains(out, "PersistentKeepalive = 25") || strings.Contains(out, "PersistentKeepalive = 0") {
		t.Fatal(out)
	}
	in = []string{"[Peer]", "PublicKey = x", "Endpoint = 1.2.3.4:51820"}
	out = strings.Join(ensureKeepalive(in), "\n")
	if !strings.Contains(out, "PersistentKeepalive = 25") {
		t.Fatal(out)
	}
}
