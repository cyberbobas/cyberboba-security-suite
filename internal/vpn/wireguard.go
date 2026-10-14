package vpn

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cyberboba/internal/config"
)

// wireguard drives wg-quick. For selective profiles the configuration is
// rewritten with `Table = off` so that wg-quick does not hijack the default
// route; cyberboba then installs its own policy routing table.
type wireguard struct {
	m       *Manager
	t       *tunnel
	log     ringLog
	runConf string
}

// renderConfig returns the wg-quick config to use and the interface name.
func (w *wireguard) renderConfig() (string, string, error) {
	src, err := os.ReadFile(w.t.profile.Config)
	if err != nil {
		return "", "", err
	}
	iface := InterfaceName(w.t.profile)
	selective := w.t.profile.Mode == config.VPNModeSelective
	var out []string
	inInterface := false
	tableSet := false
	for _, line := range strings.Split(string(src), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") {
			if inInterface && selective && !tableSet {
				out = append(out, "Table = off")
				tableSet = true
			}
			inInterface = strings.EqualFold(trim, "[Interface]")
		}
		if inInterface && selective {
			key := strings.ToLower(strings.TrimSpace(strings.SplitN(trim, "=", 2)[0]))
			if key == "table" {
				out = append(out, "Table = off")
				tableSet = true
				continue
			}
			if key == "dns" {
				// resolvconf integration is not wanted for selective mode
				out = append(out, "# "+line)
				continue
			}
		}
		out = append(out, line)
	}
	if inInterface && selective && !tableSet {
		out = append(out, "Table = off")
	}
	dir := filepath.Join(w.m.RunDir, "wg")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	path := filepath.Join(dir, iface+".conf")
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o600); err != nil {
		return "", "", err
	}
	return path, iface, nil
}

func (w *wireguard) Up() error {
	path, iface, err := w.renderConfig()
	if err != nil {
		return err
	}
	w.runConf = path
	if interfaceExists(iface) {
		w.log.add("interface already exists, bringing it down first")
		_ = exec.Command("wg-quick", "down", path).Run()
	}
	cmd := exec.Command("wg-quick", "up", path)
	out, err := cmd.CombinedOutput()
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			w.log.add(l)
		}
	}
	if err != nil {
		return fmt.Errorf("wg-quick up: %v: %s", err, lastLine(string(out)))
	}
	if err := w.m.route(w.t, iface, "", ""); err != nil {
		_ = exec.Command("wg-quick", "down", path).Run()
		return fmt.Errorf("routing: %w", err)
	}
	w.t.mu.Lock()
	w.t.endpoint = w.endpointFromConfig()
	w.t.mu.Unlock()
	w.m.markUp(w.t, iface)
	w.m.logf("info", "vpn %s: wireguard interface %s up", w.t.profile.Name, iface)
	return nil
}

func (w *wireguard) Down() error {
	path := w.runConf
	if path == "" {
		var err error
		if path, _, err = w.renderConfig(); err != nil {
			return err
		}
	}
	if !interfaceExists(InterfaceName(w.t.profile)) {
		return nil
	}
	out, err := exec.Command("wg-quick", "down", path).CombinedOutput()
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			w.log.add(l)
		}
	}
	if err != nil {
		return fmt.Errorf("wg-quick down: %v: %s", err, lastLine(string(out)))
	}
	w.m.logf("info", "vpn %s: wireguard interface down", w.t.profile.Name)
	return nil
}

func (w *wireguard) Refresh(s *Status) {
	if s.State != StateUp {
		return
	}
	if !interfaceExists(s.Interface) {
		s.State = StateDown
		s.Since = nil
		go w.m.lost(w.t, fmt.Errorf("interface %s disappeared", s.Interface))
		return
	}
	out, err := exec.Command("wg", "show", s.Interface, "dump").Output()
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var rx, tx int64
	var latest int64
	endpoint := ""
	for i, l := range lines {
		if i == 0 {
			continue // interface line
		}
		f := strings.Split(l, "\t")
		if len(f) < 8 {
			continue
		}
		if f[2] != "(none)" && endpoint == "" {
			endpoint = f[2]
		}
		hs, _ := strconv.ParseInt(f[4], 10, 64)
		if hs > latest {
			latest = hs
			endpoint = f[2]
		}
		r, _ := strconv.ParseInt(f[5], 10, 64)
		t, _ := strconv.ParseInt(f[6], 10, 64)
		rx += r
		tx += t
	}
	s.RxBytes, s.TxBytes, s.Endpoint = rx, tx, endpoint
	if latest > 0 {
		ts := time.Unix(latest, 0)
		s.LastHandshake = &ts
	}
	s.LocalIP = localIPv4(s.Interface)
}

func (w *wireguard) Log() []string { return w.log.get() }

// endpointFromConfig reads the first peer Endpoint (host:port).
func (w *wireguard) endpointFromConfig() string {
	src, err := os.ReadFile(w.t.profile.Config)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(src), "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "endpoint") {
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// scanLines is a helper used by the openvpn backend as well.
func scanLines(r *bufio.Scanner, fn func(string)) {
	for r.Scan() {
		fn(r.Text())
	}
}
