package vpn

import (
	"os/exec"
	"strconv"
	"strings"

	"cyberboba/internal/config"
)

// InferMode picks full tunnel when the config captures all IPv4/IPv6
// traffic (AllowedIPs 0.0.0.0/0 or OpenVPN redirect-gateway). Otherwise
// selective — only rule-routed connections use the tunnel.
func InferMode(content string) config.VPNMode {
	lower := strings.ToLower(content)
	if strings.Contains(lower, "0.0.0.0/0") || strings.Contains(lower, "::/0") ||
		strings.Contains(lower, "redirect-gateway") {
		return config.VPNModeFull
	}
	return config.VPNModeSelective
}

// takeOverIface makes sure NetworkManager (or a leftover wg-quick) is not
// sitting on the same interface. Two managers on one WireGuard device is how
// "I clicked Up and nothing happened" happens on desktop Linux.
func takeOverIface(iface string, logf func(string, string, ...interface{})) {
	if iface == "" {
		return
	}
	if logf == nil {
		logf = func(string, string, ...interface{}) {}
	}
	releaseNetworkManager(iface, logf)
	dropWGQuickPolicy(iface, logf)
	if interfaceExists(iface) {
		if out, err := exec.Command("ip", "link", "delete", "dev", iface).CombinedOutput(); err != nil {
			logf("debug", "vpn: delete leftover %s: %v: %s", iface, err, strings.TrimSpace(string(out)))
		} else {
			logf("info", "vpn: removed leftover interface %s", iface)
		}
	}
}

func releaseNetworkManager(iface string, logf func(string, string, ...interface{})) {
	if _, err := exec.LookPath("nmcli"); err != nil {
		return
	}
	out, err := exec.Command("nmcli", "-t", "-f", "NAME,DEVICE,TYPE", "connection", "show").CombinedOutput()
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// NAME:DEVICE:TYPE — NAME may contain colons, TYPE/DEVICE are last two.
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		typ := f[len(f)-1]
		dev := f[len(f)-2]
		name := strings.Join(f[:len(f)-2], ":")
		if typ != "wireguard" && typ != "vpn" && typ != "tun" {
			if dev != iface {
				continue
			}
		}
		if dev != iface && name != iface {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		if o, err := exec.Command("nmcli", "connection", "down", name).CombinedOutput(); err != nil {
			logf("debug", "vpn: nmcli down %s: %v: %s", name, err, strings.TrimSpace(string(o)))
		} else {
			logf("info", "vpn: disconnected NetworkManager connection %q so cyberboba can own %s", name, iface)
		}
		// Stop NM from racing us back up a second later.
		_ = exec.Command("nmcli", "connection", "modify", name, "connection.autoconnect", "no").Run()
	}
	_ = exec.Command("nmcli", "device", "disconnect", iface).Run()
}

// dropWGQuickPolicy removes leftover wg-quick/NetworkManager policy routing
// that sends all unmarked traffic into this interface (table 51820 +
// suppress_prefixlength 0). If that pair is left behind after a Down, the
// default route is suppressed and the internet appears "dead".
func dropWGQuickPolicy(iface string, logf func(string, string, ...interface{})) {
	if logf == nil {
		logf = func(string, string, ...interface{}) {}
	}
	tables := tablesForIface(iface)
	if len(tables) == 0 {
		return
	}
	for _, table := range tables {
		if table == 253 || table == 254 || table == 255 { // default, main, local
			continue
		}
		for _, fam := range [][]string{{"ip", "-4"}, {"ip", "-6"}} {
			_ = exec.Command(fam[0], append(fam[1:], "route", "flush", "table", strconv.Itoa(table))...).Run()
			dropRulesLookup(fam, table)
		}
		logf("info", "vpn: flushed leftover policy table %d for %s", table, iface)
	}
	dropSuppressPrefixRules()
}

func tablesForIface(iface string) []int {
	seen := map[int]bool{}
	var out []int
	for _, fam := range [][]string{{"ip", "-4"}, {"ip", "-6"}} {
		b, err := exec.Command(fam[0], append(fam[1:], "route", "show", "table", "all")...).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, " dev "+iface+" ") && !strings.HasSuffix(line, " dev "+iface) {
				continue
			}
			table := 254 // main, if no explicit table
			if i := strings.Index(line, " table "); i >= 0 {
				rest := strings.Fields(strings.TrimSpace(line[i+7:]))
				if len(rest) > 0 {
					if n, err := strconv.Atoi(rest[0]); err == nil {
						table = n
					}
				}
			}
			if !seen[table] {
				seen[table] = true
				out = append(out, table)
			}
		}
	}
	return out
}

func dropRulesLookup(fam []string, table int) {
	for i := 0; i < 16; i++ {
		b, err := exec.Command(fam[0], append(fam[1:], "rule", "show")...).Output()
		if err != nil {
			return
		}
		pref := ""
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, " lookup "+strconv.Itoa(table)) &&
				!strings.HasSuffix(strings.TrimSpace(line), "lookup "+strconv.Itoa(table)) {
				continue
			}
			if j := strings.Index(line, ":"); j > 0 {
				pref = strings.TrimSpace(line[:j])
				break
			}
		}
		if pref == "" {
			return
		}
		if exec.Command(fam[0], append(fam[1:], "rule", "del", "pref", pref)...).Run() != nil {
			return
		}
	}
}

func dropSuppressPrefixRules() {
	for _, fam := range [][]string{{"ip", "-4"}, {"ip", "-6"}} {
		for i := 0; i < 8; i++ {
			b, err := exec.Command(fam[0], append(fam[1:], "rule", "show")...).Output()
			if err != nil {
				break
			}
			pref := ""
			for _, line := range strings.Split(string(b), "\n") {
				if !strings.Contains(line, "suppress_prefixlength") {
					continue
				}
				if j := strings.Index(line, ":"); j > 0 {
					pref = strings.TrimSpace(line[:j])
					break
				}
			}
			if pref == "" {
				break
			}
			if exec.Command(fam[0], append(fam[1:], "rule", "del", "pref", pref)...).Run() != nil {
				break
			}
		}
	}
}

// ensureKeepalive rewrites PersistentKeepalive = 0 (or missing) to 25 so the
// tunnel survives typical home-NAT timeouts.
func ensureKeepalive(lines []string) []string {
	var out []string
	inPeer := false
	hasKA := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") {
			if inPeer && !hasKA {
				out = append(out, "PersistentKeepalive = 25")
			}
			inPeer = strings.EqualFold(trim, "[Peer]")
			hasKA = false
			out = append(out, line)
			continue
		}
		if inPeer {
			key := strings.ToLower(strings.TrimSpace(strings.SplitN(trim, "=", 2)[0]))
			if key == "persistentkeepalive" {
				val := "0"
				if i := strings.Index(trim, "="); i >= 0 {
					val = strings.TrimSpace(trim[i+1:])
				}
				if val == "0" || val == "" {
					out = append(out, "PersistentKeepalive = 25")
				} else {
					out = append(out, line)
				}
				hasKA = true
				continue
			}
		}
		out = append(out, line)
	}
	if inPeer && !hasKA {
		out = append(out, "PersistentKeepalive = 25")
	}
	return out
}
