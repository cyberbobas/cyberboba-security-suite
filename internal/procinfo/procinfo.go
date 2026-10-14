// Package procinfo maps TCP connections back to the process that owns them
// using /proc/net/tcp{,6} and /proc/<pid>/fd, the same way `ss -p` does.
package procinfo

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Process is the identity of a process that owns a socket.
type Process struct {
	PID  int
	Name string // comm
	Exe  string // resolved /proc/pid/exe
	Cmd  string
	UID  int
	User string
	Tag  string // CYBERBOBA_TAG from environ
}

type sockEntry struct {
	local  netip.AddrPort
	remote netip.AddrPort
	uid    int
	inode  uint64
}

// Resolver caches pid metadata and the inode->pid mapping.
type Resolver struct {
	mu       sync.Mutex
	procs    map[int]*Process // pid -> info
	inodes   map[uint64]int   // inode -> pid (last scan)
	lastScan time.Time
	users    map[int]string
}

// New creates a Resolver.
func New() *Resolver {
	return &Resolver{procs: map[int]*Process{}, inodes: map[uint64]int{}, users: map[int]string{}}
}

// Lookup finds the process owning the client socket local=src remote=dst.
// For a REDIRECTed connection, src is the accepted conn's RemoteAddr and dst
// is the original destination (SO_ORIGINAL_DST).
func (r *Resolver) Lookup(src, dst netip.AddrPort) (*Process, int, error) {
	entries, err := readSockets(src.Addr().Is6() && !src.Addr().Is4In6())
	if err != nil {
		return nil, -1, err
	}
	var found *sockEntry
	for i := range entries {
		e := &entries[i]
		if e.local.Port() != src.Port() {
			continue
		}
		if !e.local.Addr().Unmap().IsUnspecified() && e.local.Addr().Unmap() != src.Addr().Unmap() {
			continue
		}
		if e.remote.Port() != dst.Port() || e.remote.Addr().Unmap() != dst.Addr().Unmap() {
			continue
		}
		found = e
		break
	}
	if found == nil {
		return nil, -1, fmt.Errorf("socket %v->%v not found in /proc/net/tcp", src, dst)
	}
	pid := r.pidForInode(found.inode)
	if pid <= 0 {
		return nil, found.uid, fmt.Errorf("no process owns inode %d", found.inode)
	}
	p := r.process(pid)
	if p.UID < 0 {
		p.UID = found.uid
		p.User = r.userName(found.uid)
	}
	return p, found.uid, nil
}

// ListeningPID returns the pid listening on addr (for proxy loop detection).
func (r *Resolver) ListeningPID(addr netip.AddrPort) int {
	for _, v6 := range []bool{false, true} {
		entries, err := readSockets(v6)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.local.Port() != addr.Port() || e.remote.Port() != 0 {
				continue
			}
			la := e.local.Addr().Unmap()
			if la.IsUnspecified() || la == addr.Addr().Unmap() {
				if pid := r.pidForInode(e.inode); pid > 0 {
					return pid
				}
			}
		}
	}
	return 0
}

// Snapshot returns distinct running processes (for UI autocomplete).
func (r *Resolver) Snapshot() []Process {
	des, _ := os.ReadDir("/proc")
	seen := map[string]bool{}
	var out []Process
	for _, de := range des {
		pid, err := strconv.Atoi(de.Name())
		if err != nil {
			continue
		}
		p := r.process(pid)
		if p.Name == "" || seen[p.Exe+"|"+p.Name] {
			continue
		}
		seen[p.Exe+"|"+p.Name] = true
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (r *Resolver) pidForInode(inode uint64) int {
	r.mu.Lock()
	pid, ok := r.inodes[inode]
	fresh := time.Since(r.lastScan) < 20*time.Millisecond
	r.mu.Unlock()
	if ok && verifyInode(pid, inode) {
		return pid
	}
	// Unknown or stale: rescan /proc (coalesced for bursts of new sockets).
	if !fresh || ok {
		r.scanFDs()
	}
	r.mu.Lock()
	pid = r.inodes[inode]
	r.mu.Unlock()
	if pid == 0 && fresh {
		// The socket may have been created after the last scan.
		r.scanFDs()
		r.mu.Lock()
		pid = r.inodes[inode]
		r.mu.Unlock()
	}
	return pid
}

func verifyInode(pid int, inode uint64) bool {
	want := fmt.Sprintf("socket:[%d]", inode)
	des, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return false
	}
	for _, de := range des {
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, de.Name())); err == nil && l == want {
			return true
		}
	}
	return false
}

// scanFDs rebuilds the inode->pid map by walking /proc/*/fd.
func (r *Resolver) scanFDs() {
	m := map[uint64]int{}
	des, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, de := range des {
		pid, err := strconv.Atoi(de.Name())
		if err != nil {
			continue
		}
		fdDir := "/proc/" + de.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			l, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			n, err := strconv.ParseUint(l[8:len(l)-1], 10, 64)
			if err == nil {
				m[n] = pid
			}
		}
	}
	r.mu.Lock()
	r.inodes = m
	r.lastScan = time.Now()
	r.mu.Unlock()
}

func (r *Resolver) process(pid int) *Process {
	r.mu.Lock()
	p, ok := r.procs[pid]
	r.mu.Unlock()
	if ok && p.Exe != "" {
		// Verify the pid was not recycled: compare exe again cheaply.
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && strings.TrimSuffix(exe, " (deleted)") == p.Exe {
			return p
		}
	}
	p = &Process{PID: pid, UID: -1}
	if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		p.Name = strings.TrimSpace(string(comm))
	}
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		p.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if p.Exe != "" {
		base := filepath.Base(p.Exe)
		// comm is truncated to 15 chars; prefer the executable name when it
		// is a prefix-compatible longer form.
		if len(p.Name) == 15 && strings.HasPrefix(base, p.Name) {
			p.Name = base
		}
	}
	if cl, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		p.Cmd = strings.TrimSpace(strings.ReplaceAll(string(cl), "\x00", " "))
	}
	if st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(st), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				f := strings.Fields(line)
				if len(f) > 1 {
					p.UID, _ = strconv.Atoi(f[1])
					p.User = r.userName(p.UID)
				}
				break
			}
		}
	}
	if env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
		for _, kv := range bytes.Split(env, []byte{0}) {
			if bytes.HasPrefix(kv, []byte("CYBERBOBA_TAG=")) {
				p.Tag = string(kv[len("CYBERBOBA_TAG="):])
				break
			}
		}
	}
	r.mu.Lock()
	r.procs[pid] = p
	if len(r.procs) > 4096 {
		r.procs = map[int]*Process{pid: p}
	}
	r.mu.Unlock()
	return p
}

func (r *Resolver) userName(uid int) string {
	r.mu.Lock()
	n, ok := r.users[uid]
	r.mu.Unlock()
	if ok {
		return n
	}
	n = strconv.Itoa(uid)
	if u, err := user.LookupId(n); err == nil {
		n = u.Username
	}
	r.mu.Lock()
	r.users[uid] = n
	r.mu.Unlock()
	return n
}

func readSockets(v6 bool) ([]sockEntry, error) {
	path := "/proc/net/tcp"
	if v6 {
		path = "/proc/net/tcp6"
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []sockEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		local, err1 := parseHexAddr(f[1])
		remote, err2 := parseHexAddr(f[2])
		if err1 != nil || err2 != nil {
			continue
		}
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, sockEntry{local: local, remote: remote, uid: uid, inode: inode})
	}
	return out, sc.Err()
}

// parseHexAddr decodes "0100007F:1F90" (little-endian per 32-bit word).
func parseHexAddr(s string) (netip.AddrPort, error) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return netip.AddrPort{}, fmt.Errorf("bad addr %q", s)
	}
	raw, err := hex.DecodeString(s[:i])
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for w := 0; w+4 <= len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("bad addr %q", s)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}
