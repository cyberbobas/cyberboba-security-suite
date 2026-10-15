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

// DisplayName is a non-empty label for UI/firewall prompts.
func (p *Process) DisplayName() string {
	if p == nil {
		return ""
	}
	if p.Name != "" {
		return p.Name
	}
	if p.Exe != "" {
		return filepath.Base(p.Exe)
	}
	if p.PID > 0 {
		return fmt.Sprintf("pid-%d", p.PID)
	}
	return ""
}

// TCP states from include/net/tcp_states.h (hex in /proc/net/tcp).
const (
	tcpEstablished = 0x01
	tcpSynSent     = 0x02
	tcpSynRecv     = 0x03
	tcpFinWait1    = 0x04
	tcpFinWait2    = 0x05
	tcpTimeWait    = 0x06
	tcpClose       = 0x07
	tcpCloseWait   = 0x08
	tcpLastAck     = 0x09
	tcpListen      = 0x0A
	tcpClosing     = 0x0B
)

type sockEntry struct {
	local  netip.AddrPort
	remote netip.AddrPort
	uid    int
	inode  uint64
	state  byte
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
// is the original destination (SO_ORIGINAL_DST). Optional hints are extra
// remotes to try (the proxy's listen address after iptables REDIRECT, which
// is what /proc/net/tcp often shows as rem_address).
func (r *Resolver) Lookup(src, dst netip.AddrPort, hints ...netip.AddrPort) (*Process, int, error) {
	// Fast, atomic path: ask the kernel (sock_diag) for exactly this socket.
	// The /proc walk below can miss entries while a browser opens dozens of
	// connections at once; the diag query cannot.
	if inode, uid, err := diagLookup(src, dst); err == nil && inode != 0 {
		pid := r.pidForInode(inode)
		if pid <= 0 {
			r.scanFDs()
			pid = r.pidForInode(inode)
		}
		if pid <= 0 {
			return nil, uid, fmt.Errorf("no process owns inode %d (sock_diag)", inode)
		}
		p := r.process(pid)
		if p.UID < 0 {
			p.UID = uid
			p.User = r.userName(uid)
		}
		return p, uid, nil
	}
	// Fallback: walk /proc/net/tcp{,6}. Read both tables: a dual-stack (AF_INET6) client socket talking to an
	// IPv4 peer shows up in /proc/net/tcp6 as ::ffff:a.b.c.d, never in
	// /proc/net/tcp (Node/Bun/Java/Chromium utility processes do this).
	entries, err := readSockets(false)
	if e6, err6 := readSockets(true); err6 == nil {
		entries = append(entries, e6...)
	} else if err != nil {
		return nil, -1, err
	}
	found := pickSocket(entries, src, dst, hints)
	if found == nil {
		if extra := readOtherNetNS(); len(extra) > 0 {
			found = pickSocket(append(entries, extra...), src, dst, hints)
		}
	}
	if found == nil {
		// Last resort: same local endpoint as Accept() reported, ignore remote.
		found = pickLocal(entries, src)
		if found == nil {
			if extra := readOtherNetNS(); len(extra) > 0 {
				found = pickLocal(extra, src)
			}
		}
	}
	if found == nil {
		return nil, -1, fmt.Errorf("socket %v->%v not found in /proc/net/tcp", src, dst)
	}
	if found.inode == 0 {
		// Orphaned/TIME_WAIT sockets carry inode 0; nothing to map.
		return nil, found.uid, fmt.Errorf("socket %v->%v has no inode yet", src, dst)
	}
	pid := r.pidForInode(found.inode)
	if pid <= 0 {
		r.scanFDs()
		pid = r.pidForInode(found.inode)
	}
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

// pickSocket chooses the /proc/net/tcp row for a client connection.
// After iptables REDIRECT the kernel often rewrites rem_address to the
// proxy (127.0.0.1:7470) while Accept() reports either the original source
// IP or loopback — exact (src, dst) matching misses most of those sockets.
func pickSocket(entries []sockEntry, src, dst netip.AddrPort, hints []netip.AddrPort) *sockEntry {
	type cand struct {
		e *sockEntry
		s int
	}
	var best cand
	nEst := 0
	var uniqueEst *sockEntry
	for i := range entries {
		e := &entries[i]
		sc := scoreSocket(e, src, dst, hints)
		if sc < 0 {
			continue
		}
		if e.state == tcpEstablished && e.local.Port() == src.Port() {
			nEst++
			uniqueEst = e
		}
		if sc > best.s {
			best = cand{e: e, s: sc}
		}
	}
	if best.e != nil && best.s >= 12 {
		return best.e
	}
	if nEst == 1 {
		return uniqueEst
	}
	if best.e != nil && best.s >= 6 {
		return best.e
	}
	return nil
}

func pickLocal(entries []sockEntry, src netip.AddrPort) *sockEntry {
	sr := src.Addr().Unmap()
	var fallback *sockEntry
	n := 0
	for i := range entries {
		e := &entries[i]
		if e.inode == 0 || e.local.Port() != src.Port() {
			continue
		}
		switch e.state {
		case tcpListen, tcpTimeWait, tcpClose, tcpClosing:
			continue
		}
		if e.local.Addr().Unmap() == sr {
			return e
		}
		if e.state == tcpEstablished {
			n++
			fallback = e
		}
	}
	if n == 1 {
		return fallback
	}
	return nil
}

// readOtherNetNS reads /proc/<pid>/net/tcp{,6} for processes whose network
// namespace is not the daemon's (Flatpak, some Chromium sandboxes, containers).
func readOtherNetNS() []sockEntry {
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil
	}
	des, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	seen := map[string]bool{self: true}
	var out []sockEntry
	for _, de := range des {
		pid := de.Name()
		if pid[0] < '1' || pid[0] > '9' {
			continue
		}
		ns, err := os.Readlink("/proc/" + pid + "/ns/net")
		if err != nil || seen[ns] {
			continue
		}
		seen[ns] = true
		if v4, err := readSocketsPath("/proc/" + pid + "/net/tcp"); err == nil {
			out = append(out, v4...)
		}
		if v6, err := readSocketsPath("/proc/" + pid + "/net/tcp6"); err == nil {
			out = append(out, v6...)
		}
	}
	return out
}

func scoreSocket(e *sockEntry, src, dst netip.AddrPort, hints []netip.AddrPort) int {
	switch e.state {
	case tcpListen, tcpTimeWait, tcpClose, tcpClosing:
		return -1
	}
	if e.inode == 0 {
		return -1
	}
	if e.local.Port() != src.Port() {
		return -1
	}
	sl := e.local.Addr().Unmap()
	sr := src.Addr().Unmap()
	er := e.remote.Addr().Unmap()
	dr := dst.Addr().Unmap()
	score := 0
	if sl == sr {
		score += 10
	} else if sl.IsUnspecified() {
		score += 6
	} else if sl.IsLoopback() || sr.IsLoopback() {
		// REDIRECT: proxy sees 127.0.0.1, app bound to the NIC address.
		score += 6
	} else {
		score += 1
	}
	if er == dr && e.remote.Port() == dst.Port() {
		score += 40
	} else if e.remote.Port() == dst.Port() {
		score += 6
	}
	for _, h := range hints {
		if !h.IsValid() {
			continue
		}
		if e.remote.Port() == h.Port() {
			// REDIRECT rewrites rem to the proxy port; the address may be
			// loopback or the tunnel IP (10.x) rather than 127.0.0.1.
			score += 14
			if er == h.Addr().Unmap() || er.IsLoopback() {
				score += 6
			}
			break
		}
	}
	if er.IsLoopback() {
		score += 8
	}
	switch e.state {
	case tcpEstablished:
		score += 4
	case tcpSynSent, tcpSynRecv:
		score += 2
	}
	return score
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
			if err != nil {
				continue
			}
			// A socket inherited across fork shows up in several processes
			// (bash's /dev/tcp fd in its `sleep` child, a browser's helper).
			// /proc lists pids ascending, so keeping the first mapping
			// attributes the connection to the parent that opened it.
			if _, seen := m[n]; !seen {
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

// UserName resolves a uid to a login name (cached).
func (r *Resolver) UserName(uid int) string { return r.userName(uid) }

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
	return readSocketsPath(path)
}

func readSocketsPath(path string) ([]sockEntry, error) {
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
		st, _ := strconv.ParseUint(f[3], 16, 8)
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, sockEntry{local: local, remote: remote, uid: uid, inode: inode, state: byte(st)})
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
