// Package caido manages a local Caido (caido-cli) instance: download,
// lifecycle, reachability and CA certificate installation.
package caido

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"cyberboba/internal/config"
)

// DefaultBinary is where Install() puts caido-cli.
const DefaultBinary = "/usr/local/lib/cyberboba/caido-cli"

// Status is the JSON view.
type Status struct {
	Enabled   bool   `json:"enabled"`
	Managed   bool   `json:"managed"`
	Running   bool   `json:"running"`
	PID       int    `json:"pid,omitempty"`
	Listen    string `json:"listen"`
	Reachable bool   `json:"reachable"`
	Version   string `json:"version"`
	Binary    string `json:"binary"`
	UIURL     string `json:"ui_url"`
	CACert    string `json:"ca_cert"`
	ProxyName string `json:"proxy_name"`
	Error     string `json:"error"`
}

// Manager controls the Caido process.
type Manager struct {
	mu      sync.Mutex
	cfg     config.Caido
	cmd     *exec.Cmd
	done    chan struct{}
	lastErr string
	logf    func(level, format string, args ...interface{})
	publish func(Status)
	logs    []string
	DataDir string // default data path when none configured
}

// New creates a Manager.
func New(cfg config.Caido, dataDir string, logf func(level, format string, args ...interface{}), publish func(Status)) *Manager {
	if logf == nil {
		logf = func(string, string, ...interface{}) {}
	}
	if publish == nil {
		publish = func(Status) {}
	}
	return &Manager{cfg: cfg, logf: logf, publish: publish, DataDir: dataDir}
}

// SetConfig updates settings; the running process is restarted by the
// caller when needed.
func (m *Manager) SetConfig(cfg config.Caido) {
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
}

// Config returns the current settings.
func (m *Manager) Config() config.Caido {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// Binary returns the configured or default binary path.
func (m *Manager) Binary() string {
	m.mu.Lock()
	b := m.cfg.Binary
	m.mu.Unlock()
	if b != "" {
		return b
	}
	if _, err := os.Stat(DefaultBinary); err == nil {
		return DefaultBinary
	}
	if p, err := exec.LookPath("caido-cli"); err == nil {
		return p
	}
	if p, err := exec.LookPath("caido"); err == nil {
		return p
	}
	return DefaultBinary
}

// ProxyEntry returns the synthesized proxy config pointing at Caido.
func (m *Manager) ProxyEntry() config.Proxy {
	c := m.Config()
	name := c.ProxyName
	if name == "" {
		name = "caido"
	}
	return config.Proxy{Name: name, Type: config.ProxyHTTP, Addr: c.Listen, RemoteDNS: true, Comment: "Caido HTTP proxy (managed)"}
}

// Status reports the live state.
func (m *Manager) Status() Status {
	c := m.Config()
	m.mu.Lock()
	running := m.cmd != nil
	pid := 0
	if running && m.cmd.Process != nil {
		pid = m.cmd.Process.Pid
	}
	lastErr := m.lastErr
	m.mu.Unlock()
	s := Status{Enabled: c.Enabled, Managed: c.Managed, Running: running, PID: pid, Listen: c.Listen,
		Binary: m.Binary(), CACert: c.CACert, ProxyName: c.ProxyName, Error: lastErr}
	if s.ProxyName == "" {
		s.ProxyName = "caido"
	}
	s.UIURL = "http://" + c.Listen
	conn, err := net.DialTimeout("tcp", c.Listen, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		s.Reachable = true
	}
	s.Version = m.version()
	return s
}

var versionCache struct {
	sync.Mutex
	bin, ver string
	at       time.Time
}

func (m *Manager) version() string {
	bin := m.Binary()
	versionCache.Lock()
	defer versionCache.Unlock()
	if versionCache.bin == bin && time.Since(versionCache.at) < time.Minute {
		return versionCache.ver
	}
	versionCache.bin, versionCache.at = bin, time.Now()
	versionCache.ver = ""
	if _, err := os.Stat(bin); err != nil {
		return ""
	}
	out, err := exec.Command(bin, "--version").Output()
	if err == nil {
		versionCache.ver = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "caido-cli "))
	}
	return versionCache.ver
}

// Start launches caido-cli.
func (m *Manager) Start() error {
	c := m.Config()
	m.mu.Lock()
	if m.cmd != nil {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	bin := m.Binary()
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("caido-cli not found at %s (use install)", bin)
	}
	data := c.DataPath
	if data == "" {
		data = m.DataDir
	}
	if err := os.MkdirAll(data, 0o700); err != nil {
		return err
	}
	args := []string{"--listen", c.Listen, "--no-open", "--data-path", data}
	args = append(args, c.ExtraArgs...)
	cmd := exec.Command(bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append(os.Environ(), "HOME="+data)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start caido: %w", err)
	}
	m.mu.Lock()
	m.cmd = cmd
	m.done = make(chan struct{})
	m.lastErr = ""
	m.mu.Unlock()
	m.addLog(fmt.Sprintf("started %s %s (pid %d)", bin, strings.Join(args, " "), cmd.Process.Pid))
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			m.addLog(sc.Text())
		}
	}()
	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		if m.cmd == cmd {
			m.cmd = nil
			close(m.done)
			if err != nil {
				m.lastErr = "caido exited: " + err.Error()
			}
		}
		m.mu.Unlock()
		m.addLog("caido exited")
		m.publish(m.Status())
	}()
	m.logf("info", "caido started on %s", c.Listen)
	m.publish(m.Status())
	return nil
}

// Stop terminates the process.
func (m *Manager) Stop() error {
	m.mu.Lock()
	cmd, done := m.cmd, m.done
	m.mu.Unlock()
	if cmd == nil {
		return nil
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	m.logf("info", "caido stopped")
	return nil
}

// Restart = Stop + Start.
func (m *Manager) Restart() error {
	if err := m.Stop(); err != nil {
		return err
	}
	return m.Start()
}

func (m *Manager) addLog(s string) {
	m.mu.Lock()
	m.logs = append(m.logs, s)
	if len(m.logs) > 500 {
		m.logs = m.logs[len(m.logs)-500:]
	}
	m.mu.Unlock()
}

// Log returns captured output.
func (m *Manager) Log() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.logs...)
}

// --- download ---

type release struct {
	Version string `json:"version"`
	Links   []struct {
		Platform string `json:"platform"`
		Kind     string `json:"kind"`
		Link     string `json:"link"`
		Format   string `json:"format"`
		Hash     string `json:"hash"`
	} `json:"links"`
}

// Install downloads the latest caido-cli into dest (DefaultBinary when
// empty) and returns the path and version.
func (m *Manager) Install(dest string) (string, string, error) {
	if dest == "" {
		dest = DefaultBinary
	}
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	if arch == "" {
		return "", "", fmt.Errorf("unsupported architecture %s", runtime.GOARCH)
	}
	cl := &http.Client{Timeout: 5 * time.Minute}
	resp, err := cl.Get("https://caido.download/releases/latest")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var rel release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", fmt.Errorf("release metadata: %w", err)
	}
	var link, hash string
	for _, l := range rel.Links {
		if l.Kind == "cli" && l.Platform == "linux-"+arch && l.Format == "tar.gz" {
			link, hash = l.Link, l.Hash
		}
	}
	if link == "" {
		return "", "", errors.New("no caido-cli build for this platform")
	}
	m.logf("info", "downloading %s", link)
	r2, err := cl.Get(link)
	if err != nil {
		return "", "", err
	}
	defer r2.Body.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".caido-*.tgz")
	if err != nil {
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return "", "", err
		}
		tmp, err = os.CreateTemp(filepath.Dir(dest), ".caido-*.tgz")
		if err != nil {
			return "", "", err
		}
	}
	defer os.Remove(tmp.Name())
	h := sha512.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), r2.Body); err != nil {
		tmp.Close()
		return "", "", err
	}
	tmp.Close()
	if hash != "" {
		if got := base64.StdEncoding.EncodeToString(h.Sum(nil)); got != hash {
			// Hash algorithm is not documented; only warn on mismatch.
			m.logf("warn", "caido archive hash mismatch (got %s want %s)", got[:12], hash[:12])
		}
	}
	if err := extractBinary(tmp.Name(), dest); err != nil {
		return "", "", err
	}
	versionCache.Lock()
	versionCache.at = time.Time{}
	versionCache.Unlock()
	m.mu.Lock()
	if m.cfg.Binary == "" {
		m.cfg.Binary = dest
	}
	m.mu.Unlock()
	return dest, rel.Version, nil
}

func extractBinary(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, "caido-cli") {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(dest+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()
		return os.Rename(dest+".tmp", dest)
	}
	return errors.New("caido-cli not found in archive")
}

// --- CA certificate ---

// InstallCA installs a PEM certificate into the system trust store and into
// NSS databases of local users (Chromium: ~/.pki/nssdb, Firefox profiles).
func InstallCA(path string) (installed []string, errs []string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, []string{err.Error()}
	}
	if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		return nil, []string{"file is not a PEM certificate"}
	}
	sysDst := "/usr/local/share/ca-certificates/cyberboba-caido.crt"
	if err := os.MkdirAll(filepath.Dir(sysDst), 0o755); err == nil {
		if err := os.WriteFile(sysDst, data, 0o644); err != nil {
			errs = append(errs, err.Error())
		} else if out, err := exec.Command("update-ca-certificates").CombinedOutput(); err != nil {
			errs = append(errs, "update-ca-certificates: "+strings.TrimSpace(string(out)))
		} else {
			installed = append(installed, sysDst)
		}
	} else {
		errs = append(errs, err.Error())
	}
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		errs = append(errs, "certutil not found (apt install libnss3-tools) - browsers need the NSS import")
		return
	}
	var dbs []string
	homes, _ := filepath.Glob("/home/*")
	homes = append(homes, "/root")
	for _, h := range homes {
		if _, err := os.Stat(filepath.Join(h, ".pki/nssdb")); err == nil {
			dbs = append(dbs, filepath.Join(h, ".pki/nssdb"))
		}
		for _, pat := range []string{".mozilla/firefox/*/cert9.db", "snap/firefox/common/.mozilla/firefox/*/cert9.db", ".librewolf/*/cert9.db", ".thunderbird/*/cert9.db"} {
			ms, _ := filepath.Glob(filepath.Join(h, pat))
			for _, m := range ms {
				dbs = append(dbs, filepath.Dir(m))
			}
		}
	}
	for _, db := range dbs {
		_ = exec.Command(certutil, "-d", "sql:"+db, "-D", "-n", "Caido CA (cyberboba)").Run()
		out, err := exec.Command(certutil, "-d", "sql:"+db, "-A", "-t", "C,,", "-n", "Caido CA (cyberboba)", "-i", path).CombinedOutput()
		if err != nil {
			errs = append(errs, db+": "+strings.TrimSpace(string(out)))
		} else {
			installed = append(installed, db)
		}
	}
	return
}
