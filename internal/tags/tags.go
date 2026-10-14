// Package tags groups processes launched with `cyberboba run -tag NAME` into
// net_cls cgroups so that their traffic - including UDP (QUIC, games, VoIP)
// which the transparent TCP proxy cannot see - can be marked for a VPN
// routing table or rejected by netfilter.
package tags

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// base net_cls hierarchy.
const (
	netClsRoot   = "/sys/fs/cgroup/net_cls"
	cyberbobaDir = "cyberboba"
	classMajor   = 0x0074
)

// Tag is a live tag group.
type Tag struct {
	Name    string `json:"tag"`
	ClassID string `json:"classid"`
	classid uint32
	Pids    []int  `json:"pids"`
	UDP     string `json:"udp_action"` // "", "vpn:name", "block"
}

// Manager owns the net_cls cgroups.
type Manager struct {
	mu     sync.Mutex
	tags   map[string]*Tag
	nextID uint32
	avail  bool
}

// New creates a Manager and probes for net_cls support.
func New() *Manager {
	m := &Manager{tags: map[string]*Tag{}, nextID: 1}
	if st, err := os.Stat(netClsRoot); err == nil && st.IsDir() {
		m.avail = true
	}
	return m
}

// Available reports whether net_cls cgroups can be used.
func (m *Manager) Available() bool { return m.avail }

func (m *Manager) dir(tag string) string {
	return filepath.Join(netClsRoot, cyberbobaDir, sanitize(tag))
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "tag"
	}
	return b.String()
}

// Ensure creates the cgroup for a tag and returns its classid.
func (m *Manager) Ensure(tag string) (*Tag, error) {
	if !m.avail {
		return nil, fmt.Errorf("net_cls cgroup not available")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tags[tag]; ok {
		return t, nil
	}
	id := m.nextID
	m.nextID++
	classid := uint32(classMajor)<<16 | id
	dir := m.dir(tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "net_cls.classid"), []byte(strconv.FormatUint(uint64(classid), 10)), 0o644); err != nil {
		return nil, err
	}
	t := &Tag{Name: tag, ClassID: fmt.Sprintf("0x%08x", classid), classid: classid}
	m.tags[tag] = t
	return t, nil
}

// Attach moves a process into the tag's cgroup.
func (m *Manager) Attach(pid int, tag string) error {
	if _, err := m.Ensure(tag); err != nil {
		return err
	}
	dir := m.dir(tag)
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return fmt.Errorf("attach pid %d to tag %s: %w", pid, tag, err)
	}
	return nil
}

// ClassID returns the classid for a tag, creating it if needed.
func (m *Manager) ClassID(tag string) (uint32, string, error) {
	t, err := m.Ensure(tag)
	if err != nil {
		return 0, "", err
	}
	return t.classid, t.ClassID, nil
}

// pids reads the live pids in a tag's cgroup.
func (m *Manager) pids(tag string) []int {
	data, err := os.ReadFile(filepath.Join(m.dir(tag), "cgroup.procs"))
	if err != nil {
		return nil
	}
	var out []int
	for _, line := range strings.Fields(string(data)) {
		if n, err := strconv.Atoi(line); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// SetUDPAction records the UDP policy label for a tag (display only).
func (m *Manager) SetUDPAction(tag, action string) {
	m.mu.Lock()
	if t, ok := m.tags[tag]; ok {
		t.UDP = action
	}
	m.mu.Unlock()
}

// List returns the current tags with live pids.
func (m *Manager) List() []Tag {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Tag, 0, len(m.tags))
	for _, t := range m.tags {
		cp := *t
		cp.Pids = m.pids(t.Name)
		if cp.Pids == nil {
			cp.Pids = []int{}
		}
		out = append(out, cp)
	}
	return out
}

// Names returns the known tag names.
func (m *Manager) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for n := range m.tags {
		out = append(out, n)
	}
	return out
}

// Cleanup removes all cyberboba cgroups (best effort, on shutdown).
func (m *Manager) Cleanup() {
	if !m.avail {
		return
	}
	root := filepath.Join(netClsRoot, cyberbobaDir)
	entries, _ := os.ReadDir(root)
	for _, de := range entries {
		if de.IsDir() {
			_ = os.Remove(filepath.Join(root, de.Name()))
		}
	}
	_ = os.Remove(root)
}
